import http.server
import ssl
import threading
import json
import os
import time
import mimetypes
import base64
import hashlib
import hmac
import secrets
from urllib.parse import urlparse, parse_qs, unquote

HOST, PORT = '0.0.0.0', 8443
MESSAGE_FILE = 'messages.jsonl'
UPLOAD_DIR = 'uploads'
USERS_FILE = 'users.json'
SECRET_FILE = 'secret.txt'
condition = threading.Condition()
messages = []

# Загрузка существующих сообщений
if os.path.exists(MESSAGE_FILE):
    with open(MESSAGE_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                messages.append(json.loads(line.strip()))
            except:
                continue

# Подготовка секрета для подписи cookie
def load_secret():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, 'rb') as f:
            return f.read().strip()
    sec = base64.urlsafe_b64encode(os.urandom(32))
    with open(SECRET_FILE, 'wb') as f:
        f.write(sec)
    return sec

SECRET = load_secret()

# Пользователи: хранение хэшей
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def hash_password(password, salt=None, iterations=200000):
    if salt is None:
        salt = os.urandom(16)
    if isinstance(salt, str):
        salt = base64.b64decode(salt)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return {
        'salt': base64.b64encode(salt).decode('ascii'),
        'hash': base64.b64encode(dk).decode('ascii'),
        'iterations': iterations,
    }

def verify_password(password, rec):
    try:
        salt = rec['salt']
        iterations = int(rec.get('iterations', 200000))
        expected = base64.b64decode(rec['hash'])
        salt_bytes = base64.b64decode(salt)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

def sign_session(username):
    # без истечения срока: действует пока cookie не очищена
    payload = username.encode('utf-8')
    mac = hmac.new(SECRET, payload, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(payload + b'.' + mac).decode('ascii')
    return token

def verify_session(token):
    try:
        raw = base64.urlsafe_b64decode(token.encode('ascii'))
        user, mac = raw.split(b'.', 1)
        expected = hmac.new(SECRET, user, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            return None
        return user.decode('utf-8')
    except Exception:
        return None

def parse_cookies(cookie_header):
    result = {}
    if not cookie_header:
        return result
    parts = cookie_header.split(';')
    for p in parts:
        if '=' in p:
            k, v = p.split('=', 1)
            result[k.strip()] = v.strip()
    return result

class ChatHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        # Подавляем стандартный лог
        return

    def _set_headers(self, status=200, content_type="application/json", content_length=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        if content_length is not None:
            self.send_header("Content-Length", str(content_length))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Connection", "close")
        self.end_headers()

    def _require_auth(self):
        cookies = parse_cookies(self.headers.get('Cookie'))
        tok = cookies.get('session')
        user = verify_session(tok) if tok else None
        return user

    def _redirect_login(self):
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/login":
            self._serve_file("login.html", "text/html")
        elif path == "/":
            user = self._require_auth()
            if not user:
                return self._redirect_login()
            self._serve_file("index.html", "text/html")
        elif path == "/style.css":
            self._serve_file("style.css", "text/css")
        elif path == "/script.js":
            print("[GET] Запрос на /script.js")
            self._serve_file("script.js", "application/javascript")
        elif path == "/api/chats/1/messages":
            user = self._require_auth()
            if not user:
                self.send_error(401, "Unauthorized")
                return
            query = parse_qs(parsed.query)
            since = 0
            try:
                since = float(query.get("since", ["0"])[0])
            except:
                pass

            end_time = time.time() + 25
            result = []

            with condition:
                while time.time() < end_time:
                    result = [m for m in messages if m["timestamp"] > since]
                    if result:
                        break
                    condition.wait(timeout=1)

            body = json.dumps(result).encode("utf-8")
            self._set_headers(200, "application/json", content_length=len(body))
            self.wfile.write(body)
            print(f"[GET] Сообщений: {len(result)} с момента {since}")
        elif path == "/api/me":
            user = self._require_auth()
            if not user:
                self.send_error(401, "Unauthorized")
                return
            body = json.dumps({"username": user}).encode("utf-8")
            self._set_headers(200, "application/json", content_length=len(body))
            self.wfile.write(body)
        elif path.startswith("/files/"):
            user = self._require_auth()
            if not user:
                self.send_error(401, "Unauthorized")
                return
            # Раздача ранее загруженных файлов
            safe_name = unquote(path[len("/files/"):]).replace("..", "_")
            file_path = os.path.join(UPLOAD_DIR, safe_name)
            if not os.path.isfile(file_path):
                self.send_error(404, "File not found")
                return

            ctype, _ = mimetypes.guess_type(file_path)
            if not ctype:
                ctype = 'application/octet-stream'
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Disposition", f"attachment; filename=\"{os.path.basename(file_path)}\"")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                self.send_error(500, "Read error")
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        if self.path == "/api/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body.decode('utf-8'))
                username = (data.get('username') or '').strip()
                password = data.get('password') or ''
                users = load_users()
                if username in users and verify_password(password, users[username]):
                    token = sign_session(username)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Set-Cookie", f"session={token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=315360000")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b"{\"status\":\"ok\"}")
                else:
                    self.send_error(401, "Invalid credentials")
            except Exception as e:
                self.send_error(400, f"Bad request: {e}")
        elif self.path == "/api/register":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body.decode('utf-8'))
                username = (data.get('username') or '').strip()
                password = data.get('password') or ''
                if not username or not password:
                    self.send_error(400, "Username and password required")
                    return
                users = load_users()
                if username in users:
                    self.send_error(409, "User exists")
                    return
                rec = hash_password(password)
                users[username] = rec
                save_users(users)
                token = sign_session(username)
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", f"session={token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=315360000")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"{\"status\":\"ok\"}")
            except Exception as e:
                self.send_error(400, f"Bad request: {e}")
        elif self.path == "/api/logout":
            # перезатираем cookie
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Set-Cookie", "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"{\"status\":\"ok\"}")
        elif self.path == "/api/chats/1/messages":
            user = self._require_auth()
            if not user:
                self.send_error(401, "Unauthorized")
                return
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)

            try:
                data = json.loads(body.decode("utf-8"))
                text = data.get("text", "").strip()
                if not text:
                    raise ValueError("Пустой текст")
                # Используем имя из сессии, игнорируя клиентский sender
                sender = user

                msg = {
                    "timestamp": time.time(),
                    "created_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "sender": sender,
                    "text": text
                }

                with condition:
                    messages.append(msg)
                    with open(MESSAGE_FILE, 'a', encoding='utf-8') as f:
                        f.write(json.dumps(msg, ensure_ascii=False) + '\n')
                    condition.notify_all()

                body = json.dumps({"status": "ok"}).encode("utf-8")
                self._set_headers(200, "application/json", content_length=len(body))
                self.wfile.write(body)
                print("[POST] Сообщение добавлено:", msg["text"])

            except Exception as e:
                self.send_error(400, f"Ошибка формата: {e}")
        elif self.path == "/api/chats/1/upload":
            user = self._require_auth()
            if not user:
                self.send_error(401, "Unauthorized")
                return
            # multipart/form-data загрузка файла без cgi
            try:
                content_type = self.headers.get('Content-Type', '')
                if not content_type.startswith('multipart/form-data'):
                    self.send_error(400, "Expected multipart/form-data")
                    return
                # Получаем boundary
                boundary = None
                for part in content_type.split(';'):
                    part = part.strip()
                    if part.startswith('boundary='):
                        boundary = part.split('=', 1)[1]
                        break
                if not boundary:
                    self.send_error(400, "No boundary")
                    return
                boundary_bytes = ("--" + boundary).encode('utf-8')

                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length)

                # Разбиваем тело на части
                segments = body.split(boundary_bytes)
                sender = user
                file_bytes = None
                original_name = None

                for seg in segments:
                    if not seg or seg == b"--\r\n" or seg == b"--":
                        continue
                    # Убираем префикс CRLF и завершающий --/CRLF
                    if seg.startswith(b"\r\n"):
                        seg = seg[2:]
                    if seg.endswith(b"\r\n"):
                        seg = seg[:-2]
                    if seg.endswith(b"--"):
                        seg = seg[:-2]

                    header_end = seg.find(b"\r\n\r\n")
                    if header_end == -1:
                        continue
                    header_bytes = seg[:header_end]
                    content = seg[header_end+4:]

                    # Парсим заголовки части
                    headers = {}
                    for line in header_bytes.split(b"\r\n"):
                        if b":" in line:
                            k, v = line.split(b":", 1)
                            headers[k.decode().strip().lower()] = v.decode().strip()

                    disp = headers.get('content-disposition', '')
                    # Ищем name и filename
                    name = None
                    filename = None
                    for token in disp.split(';'):
                        token = token.strip()
                        if token.startswith('name='):
                            name = token.split('=',1)[1].strip('"')
                        elif token.startswith('filename='):
                            filename = token.split('=',1)[1].strip('"')

                    if name == 'file' and filename:
                        original_name = os.path.basename(filename)
                        # Убираем возможный завершающий CRLF у содержимого файла
                        if content.endswith(b"\r\n"):
                            content = content[:-2]
                        file_bytes = content

                if not file_bytes or not original_name:
                    self.send_error(400, "No file provided")
                    return

                os.makedirs(UPLOAD_DIR, exist_ok=True)
                base, ext = os.path.splitext(original_name)
                stored_name = f"{base}_{int(time.time()*1000)}{ext}"
                file_path = os.path.join(UPLOAD_DIR, stored_name)
                with open(file_path, 'wb') as out:
                    out.write(file_bytes)

                size = os.path.getsize(file_path)
                mime, _ = mimetypes.guess_type(original_name)
                if not mime:
                    mime = 'application/octet-stream'

                msg = {
                    "timestamp": time.time(),
                    "created_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "sender": sender,
                    "text": f"[file] {original_name}",
                    "file": {
                        "stored_name": stored_name,
                        "original_name": original_name,
                        "size": size,
                        "mime": mime,
                        "url": f"/files/{stored_name}"
                    }
                }

                with condition:
                    messages.append(msg)
                    with open(MESSAGE_FILE, 'a', encoding='utf-8') as f:
                        f.write(json.dumps(msg, ensure_ascii=False) + '\n')
                    condition.notify_all()

                resp = json.dumps({"status": "ok", "file": msg["file"]}).encode('utf-8')
                self._set_headers(200, "application/json", content_length=len(resp))
                self.wfile.write(resp)
                print("[UPLOAD] Файл принят:", original_name, "от", sender)
            except Exception as e:
                self.send_error(400, f"Ошибка загрузки: {e}")
        else:
            self.send_error(404, "Not Found")

    def _serve_file(self, filename, content_type):
        try:
            with open(filename, 'rb') as f:
                content = f.read()
            self._set_headers(200, content_type, content_length=len(content))
            self.wfile.write(content)
        except Exception as e:
            self.send_error(404, f"Файл не найден: {filename}")

# Запуск HTTPS-сервера
def run_server():
    httpd = http.server.ThreadingHTTPServer((HOST, PORT), ChatHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f"Server is running at https://localhost:{PORT}")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
