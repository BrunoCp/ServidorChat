import socket
import threading
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
import bcrypt
 

HOST = 'localhost'
PORT = 8000
# Diretório onde está localizado este arquivo Python
BASE_DIR = Path(__file__).resolve().parent

# Caminho absoluto do banco de dados
DATABASE_NAME = BASE_DIR / 'chat_database.db'

ONLINE_USERS = {}
ONLINE_USERS_LOCK = threading.Lock()
DB_LOCK = threading.Lock()

class ChatServer:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = [] # Mantem o controle dos sockets dos clientes, embora ONLINE_USERS seja a fonte principal para usuários ativos.
        self.setup_database()

    def conectar_banco(self):
        conexao = sqlite3.connect(
            str(DATABASE_NAME),
            timeout=10
    )

        conexao.execute("PRAGMA foreign_keys = ON")

        return conexao

    def setup_database(self):
        with DB_LOCK:
            conn = self.conectar_banco()

            try:
                cursor = conn.cursor()

            # Tabela de usuários
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL
                    )
                """)

            # Tabela de mensagens offline
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS offline_messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        receiver TEXT NOT NULL,
                        sender TEXT NOT NULL,
                        content TEXT NOT NULL,
                        timestamp TEXT NOT NULL
                )
            """)

                conn.commit()

            # Verificar as tabelas existentes
                cursor.execute("""
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                    ORDER BY name
                """)

                tabelas = cursor.fetchall()

                print("\n[DATABASE] Banco configurado com sucesso!")
                print(f"[DATABASE] Arquivo: {DATABASE_NAME}")
                print("[DATABASE] Tabelas encontradas:")

                for tabela in tabelas:
                    print(f" - {tabela[0]}")

            except sqlite3.Error as erro:
                conn.rollback()
                print(f"[DATABASE] Erro ao configurar o banco: {erro}")
                raise

            finally:
                conn.close()

    def _hash_password(self, password):
        # Gerar um salt e fazer o hash da senha.
        # O bcrypt trabalha com bytes, então codifique a senha.
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def _verify_password(self, stored_hash, provided_password):
        # Verifique se a senha fornecida corresponde ao hash armazenado.
        # bcrypt trabalha com bytes, então codifique ambos.
        try:
            return bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash.encode('utf-8'))
        except ValueError: # Trate casos em que stored_hash pode não ser um hash bcrypt válido
            return False

    def register_user(self, username, password):
        hashed_password = self._hash_password(password)
        with DB_LOCK:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
                conn.commit()
                conn.close()
                return True, "Cadastro concluído com sucesso."
            except sqlite3.IntegrityError:
                conn.close()
                return False, "Nome de usuário já existe."
            except Exception as e:
                conn.close()
                return False, f"Falha no cadastro: {e}"

    def authenticate_user(self, username, password):
        with DB_LOCK:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            conn.close()

            if result:
                stored_hash = result[0]
                if self._verify_password(stored_hash, password):
                    return True, "Login bem-sucedido."
                else:
                    return False, "Senha incorreta!"
            else:
                return False, "Nome de usuário não encontrado."

    def store_offline_message(self, receiver, sender, content, timestamp):
        with DB_LOCK:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO offline_messages (receiver, sender, content, timestamp) VALUES (?, ?, ?, ?)",
                           (receiver, sender, content, timestamp))
            conn.commit()
            conn.close()
        print(f"[SERVER] [Offline Msg] Mensagem de '{sender}' para '{receiver}' ARMAZENADO.")

    def get_offline_messages(self, receiver):
        messages = []
        with DB_LOCK:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT sender, content, timestamp FROM offline_messages WHERE receiver = ?", (receiver,))
            rows = cursor.fetchall()

            for row in rows:
                messages.append({
                    'type': 'message',
                    'sender': row[0],
                    'content': row[1],
                    'timestamp': row[2],
                    'receiver': receiver # Incluir receptor para exibição no lado do cliente
                })
            
            # Apagar mensagens depois de buscá-las
            cursor.execute("DELETE FROM offline_messages WHERE receiver = ?", (receiver,))
            conn.commit()
            conn.close()
        print(f"[SERVER] [Offline Msg] {len(messages)} mensagens ENCONTRADAS e REMOVIDAS para '{receiver}'.")
        return messages

    def get_all_registered_users(self):
        users_with_status = []
        with DB_LOCK:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users")
            all_users_db = [row[0] for row in cursor.fetchall()]
            conn.close()
        
        with ONLINE_USERS_LOCK:
            online_usernames = list(ONLINE_USERS.keys())
        
        for user in sorted(all_users_db):
            status = 'online' if user in online_usernames else 'offline'
            users_with_status.append({'username': user, 'status': status})
        
        return users_with_status

    def broadcast_user_list(self):
        all_users = self.get_all_registered_users()

        user_list_message = {
            'type': 'user_list',
            'users': all_users
        }
        
        with ONLINE_USERS_LOCK:
            for user_socket in ONLINE_USERS.values():
                try:
                    self._send_json_message(user_socket, user_list_message)
                except Exception as e:
                    print(f"[SERVER] Erro ao enviar a lista de usuários para um cliente: {e}")

    def _send_json_message(self, client_socket, message):
        try:
            message_str = json.dumps(message) + '\n'
            client_socket.send(message_str.encode('utf-8'))
            return True
        except Exception as e:
            print(f"[SERVER] Erro ao enviar JSON para o cliente: {e}")
            return False

    def handle_client(self, client_socket, address):
        print(f"[SERVER] Nova conexão de {address}")
        username = None # Vai salvar o nome de usuário assim que autenticado
        buffer = "" # Buffer para mensagens incompletas

        try:
            while True:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    print(f"[SERVER] Usuario {address} Desconectado (no data).")
                    break

                buffer += data

                while '\n' in buffer:
                    message_str, buffer = buffer.split('\n', 1)
                    if message_str.strip(): # Certifique-se de que não seja apenas uma linha vazia
                        try:
                            message = json.loads(message_str)
                            msg_type = message.get('type')
                            print(f"[SERVER] [{address}][{username if username else 'N/A'}] Recebido: {message}")

                            if msg_type == 'register':
                                req_username = message.get('username')
                                req_password = message.get('password')
                                success, msg = self.register_user(req_username, req_password)
                                self._send_json_message(client_socket, {'type': 'register_response', 'status': 'success' if success else 'failure', 'message': msg})

                            elif msg_type == 'login':
                                req_username = message.get('username')
                                req_password = message.get('password')
                                
                                success, msg = self.authenticate_user(req_username, req_password)

                                if success:
                                    with ONLINE_USERS_LOCK:
                                        if req_username in ONLINE_USERS:
                                            # Se já estiver logado, notifique a *nova* conexão e a feche
                                            self._send_json_message(client_socket, {'type': 'login_response', 'status': 'failure', 'message': 'User already logged in from another session.'})
                                            print(f"[SERVER] Tentativa de login duplicada para {req_username} de {address}.")
                                            client_socket.close() # Fechar a nova conexão
                                            return # Saia deste thread de manipulador pois a conexão está fechada.
                                        
                                        ONLINE_USERS[req_username] = client_socket
                                        username = req_username # Atribuir nome de usuário ao escopo deste manipulador.
                                    
                                    print(f"[SERVER] Usar {username} logado de {address}.")
                                    self._send_json_message(client_socket, {'type': 'login_response', 'status': 'success', 'username': username})
                                    
                                    # Enviar quaisquer mensagens offline
                                    offline_msgs = self.get_offline_messages(username)
                                    if offline_msgs:
                                        print(f"[SERVER] Enviando {len(offline_msgs)} mensagens offline para {username}.")
                                        for o_msg in offline_msgs:
                                            self._send_json_message(client_socket, o_msg)
                                    else:
                                        print(f"[SERVER] No offline messages for {username}.")
                                            
                                    self.broadcast_user_list() # Notificar todos os clientes sobre o novo usuário online.

                                else:
                                    self._send_json_message(client_socket, {'type': 'login_response', 'status': 'failure', 'message': msg})

                            elif msg_type == 'logout':
                                if username: # Certifique-se de que um usuário estava conectado nesta conexão.
                                    with ONLINE_USERS_LOCK:
                                        if username in ONLINE_USERS and ONLINE_USERS[username] == client_socket:
                                            del ONLINE_USERS[username]
                                            print(f"[SERVER] User {username} logged out.")
                                            # Avisar outros clientes que este usuário se desconectou.
                                            disconnected_message = {
                                                'type': 'user_disconnected',
                                                'username': username
                                            }
                                            for user_name, sock in ONLINE_USERS.items():
                                                try:
                                                    if sock != client_socket: # Não envie para o cliente que está saindo
                                                        self._send_json_message(sock, disconnected_message)
                                                except Exception as e:
                                                    print(f"[SERVER] Erro ao notificar {user_name} about {username}'s desconexão: {e}")
                                            
                                            self.broadcast_user_list() # Transmitir lista de usuários atualizada.
                                    username = None # Limpar nome de usuário para este identificador.
                                client_socket.close() # Feche o socket para o cliente que está desconectando.
                                return # Sair desta thread de manipulador

                            elif msg_type == 'message':
                                if username: # Permitir mensagens apenas de usuários autenticados.
                                    receiver = message.get('receiver')
                                    content = message.get('content')
                                    timestamp = message.get('timestamp', datetime.now().strftime('%H:%M:%S'))

                                    msg_to_send = {
                                        'type': 'message',
                                        'sender': username,
                                        'content': content,
                                        'timestamp': timestamp,
                                        'receiver': receiver # Inclua o receptor para a lógica do lado do cliente.
                                    }

                                    if receiver == 'all':
                                        print(f"[SERVER] [PUBLIC] From '{username}': '{content}'")
                                        with ONLINE_USERS_LOCK:
                                            for user, sock in ONLINE_USERS.items():
                                                # Enviar para todos os clientes conectados, exceto o remetente
                                                if sock != client_socket:
                                                    self._send_json_message(sock, msg_to_send)
                                    else:
                                        print(f"[SERVER] [PRIVATE] From '{username}' to '{receiver}': '{content}'")
                                        with ONLINE_USERS_LOCK:
                                            target_socket = ONLINE_USERS.get(receiver)
                                        
                                        if target_socket:
                                            self._send_json_message(target_socket, msg_to_send)
                                            print(f"[SERVER] '{receiver}' online. Encaminhando mensagem privada.")
                                        else:
                                            print(f"[SERVER] '{receiver}' offline. Armazenando mensagem privada.")
                                            self.store_offline_message(receiver, username, content, timestamp)
                                            # Opcionalmente, informe ao remetente que o destinatário está offline.
                                            self._send_json_message(client_socket, {'type': 'message_status', 'recipient': receiver, 'status': 'offline', 'message': 'Recipient offline. Message stored for future delivery.'})

                            elif msg_type == 'typing' or msg_type == 'stop_typing':
                                if username:
                                    recipient = message.get('recipient')
                                    status = 'typing' if msg_type == 'typing' else 'stopped'
                                    
                                    typing_notification = {
                                        'type': 'typing_notification',
                                        'from': username,
                                        'recipient': recipient,
                                        'status': status
                                    }

                                    if recipient == 'all':
                                        with ONLINE_USERS_LOCK:
                                            for user_name, sock in ONLINE_USERS.items():
                                                if sock != client_socket: # Não envie para si mesmo
                                                    self._send_json_message(sock, typing_notification)
                                    else:
                                        with ONLINE_USERS_LOCK:
                                            target_socket = ONLINE_USERS.get(recipient)
                                        if target_socket:
                                            self._send_json_message(target_socket, typing_notification)

                            elif msg_type == 'get_users':
                                if username: # Permitir isso apenas para usuários autenticados
                                    all_users_with_status = self.get_all_registered_users()
                                    self._send_json_message(client_socket, {'type': 'user_list', 'users': all_users_with_status})
                                    print(f"[SERVER] Lista de usuários solicitada por {username}.")

                            elif msg_type == 'ping':
                                # Mensagem de batimento cardíaco, nenhuma ação necessária além de manter a conexão viva
                                pass
                            else:
                                print(f"[SERVER] Tipo de mensagem desconhecido de {address}: {message}")

                        except json.JSONDecodeError as e:
                            print(f"[SERVER] ERROR: JSON inválido recebido de {address}: '{message_str}' - Error: {e}")
                            break # Fechar conexão em JSON inválido
                        except Exception as e:
                            print(f"[SERVER] ERROR: Erro ao processar a mensagem de {address}: {e}")
                            break # Fechar conexão em outros erros de processamento

        except Exception as e:
            print(f"[SERVER] ERROR: Erro de comunicação com o cliente {address}: {e}")
        finally:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            # Este bloco sempre é executado quando o cliente se desconecta ou ocorre um erro.
            if username: # Somente se um nome de usuário foi associado com sucesso a esta conexão.
                with ONLINE_USERS_LOCK:
                    # Dá uma conferida pra garantir que o socket em ONLINE_USERS é realmente o que está desconectando
                    if username in ONLINE_USERS and ONLINE_USERS[username] == client_socket:
                        del ONLINE_USERS[username]
                        print(f"[SERVER] User {username} desconectado (cleanup from online list).")
                        
                        # Transmitir mensagem de usuário_desconectado para todos os usuários online restantes.
                        disconnected_message = {
                            'type': 'user_disconnected',
                            'username': username
                        }
                        for user_name, sock in ONLINE_USERS.items():
                            try:
                                # Certifique-se de que não tentemos enviar para o socket que acabou de desconectar.
                                if sock != client_socket: 
                                    self._send_json_message(sock, disconnected_message)
                            except Exception as e:
                                print(f"[SERVER] Erro ao notificar {user_name} sobre {username}'s desconexão: {e}")
                        
                        self.broadcast_user_list() # Transmita a lista de usuários atualizada após a remoção e notificação.
            
            try:
                # Tente fechar os dois lados do socket de forma tranquila.
                client_socket.shutdown(socket.SHUT_RDWR) 
                client_socket.close()
            except Exception as e:
                print(f"[SERVER] Erro ao fechar o socket para {address}: {e}")

    def start(self):
        try:
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen(5)
            print(f"[SERVER] Servidor ouvindo em {HOST}:{PORT}")

            while True:
                client_socket, address = self.server_socket.accept()
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True)
                client_handler.start()
                self.clients.append(client_socket) # Acompanhar os clientes geralmente é uma boa prática.

        except Exception as e:
            print(f"[SERVER] ERROR: Erro ao iniciar o servidor: {e}")
        finally:
            print("[SERVER] Servidor desligando.")
            self.server_socket.close()
            with ONLINE_USERS_LOCK:
                # Fechar todos os sockets de cliente que ainda estão marcados como online quando o servidor desligar
                for sock in ONLINE_USERS.values():
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                        sock.close()
                    except:
                        pass
                ONLINE_USERS.clear()


if __name__ == "__main__":
    server = ChatServer()
    server.start()