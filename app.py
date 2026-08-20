from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import bcrypt
import jwt
import datetime
import json
import re
import time
import os
import random

app = Flask(__name__)
CORS(app)

SECRET_KEY = "спокойный_ум_секрет_2026"
DEBUG_MODE = True  # Если True — не требует почту для тестов

# ---- ЗАЩИТА ОТ БРУТФОРСА ----
login_attempts = {}

def is_blocked(ip):
    if ip in login_attempts:
        data = login_attempts[ip]
        if data['blocked_until'] and data['blocked_until'] > time.time():
            return True
    return False

def record_failed_attempt(ip):
    if ip not in login_attempts:
        login_attempts[ip] = {'attempts': 0, 'blocked_until': None}
    login_attempts[ip]['attempts'] += 1
    if login_attempts[ip]['attempts'] >= 5:
        login_attempts[ip]['blocked_until'] = time.time() + 300

def reset_attempts(ip):
    if ip in login_attempts:
        login_attempts[ip] = {'attempts': 0, 'blocked_until': None}

# ---- БАЗА ДАННЫХ ----
def init_db():
    if os.path.exists('social.db'):
        os.remove('social.db')
        print("🗑️ Старая база удалена")
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            email TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            text TEXT,
            mood TEXT DEFAULT '·',
            media TEXT,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            text TEXT NOT NULL,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read BOOLEAN DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS moods (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            mood TEXT NOT NULL,
            date DATE DEFAULT CURRENT_DATE
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gratitude (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            text TEXT NOT NULL,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS likes (
            post_id INTEGER,
            user_id INTEGER,
            PRIMARY KEY (post_id, user_id),
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Тестовые пользователи
    alex_hash = bcrypt.hashpw("alex123".encode(), bcrypt.gensalt())
    marina_hash = bcrypt.hashpw("marina123".encode(), bcrypt.gensalt())
    
    cursor.execute(
        "INSERT INTO users (username, password_hash, display_name, email) VALUES (?, ?, ?, ?)",
        ["alex", alex_hash, "Алекс", "alex@example.com"]
    )
    cursor.execute(
        "INSERT INTO users (username, password_hash, display_name, email) VALUES (?, ?, ?, ?)",
        ["marina", marina_hash, "Марина", "marina@example.com"]
    )
    
    cursor.execute("INSERT INTO posts (user_id, text, mood) VALUES (?, ?, ?)", [1, "тишина — это тоже голос", "·"])
    cursor.execute("INSERT INTO posts (user_id, text, mood) VALUES (?, ?, ?)", [2, "заметил, как дышит ветер", "◌"])
    
    conn.commit()
    conn.close()
    print("✅ База данных создана!")

def get_user_by_token(token):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        conn = sqlite3.connect('social.db')
        cursor = conn.cursor()
        user = cursor.execute(
            "SELECT id, username, display_name, email FROM users WHERE id = ?",
            [data['user_id']]
        ).fetchone()
        conn.close()
        return user
    except:
        return None

def get_user_by_username(username):
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    user = cursor.execute(
        "SELECT id, username, password_hash, display_name, email FROM users WHERE username = ?",
        [username]
    ).fetchone()
    conn.close()
    return user

def get_user_by_email(email):
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    user = cursor.execute(
        "SELECT id, username, password_hash, display_name, email FROM users WHERE email = ?",
        [email]
    ).fetchone()
    conn.close()
    return user

def get_user_by_login(login):
    if '@' in login:
        return get_user_by_email(login)
    return get_user_by_username(login)

# ============================================================
# ЭНДПОИНТЫ
# ============================================================

# ---- РЕГИСТРАЦИЯ ----
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    display_name = data.get('display_name', username)
    email = data.get('email', '').strip().lower()
    
    if not username or not password:
        return jsonify({"success": False, "message": "Заполните все поля"})
    
    if len(password) < 8:
        return jsonify({"success": False, "message": "Пароль минимум 8 символов"})
    
    if not re.search(r'[A-Z]', password):
        return jsonify({"success": False, "message": "Пароль должен содержать заглавную букву"})
    
    if not re.search(r'\d', password):
        return jsonify({"success": False, "message": "Пароль должен содержать цифру"})
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"success": False, "message": "Юзернейм: только латиница, цифры и _"})
    
    # Если DEBUG_MODE включён — email не обязателен
    if not DEBUG_MODE and (not email or '@' not in email):
        return jsonify({"success": False, "message": "Введите корректный email"})
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    
    try:
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (username, password_hash, display_name, email) VALUES (?, ?, ?, ?)",
            [username, password_hash, display_name, email or f"{username}@example.com"]
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Регистрация успешна!"})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"success": False, "message": "Пользователь уже существует"})

# ---- ВХОД ----
@app.route('/api/login', methods=['POST'])
def login():
    ip = request.remote_addr
    data = request.json
    login = data.get('login', '').strip().lower()
    password = data.get('password', '')
    
    if not login or not password:
        return jsonify({"success": False, "message": "Заполните все поля"})
    
    if is_blocked(ip):
        return jsonify({"success": False, "message": "Слишком много попыток. Подождите 5 минут."})
    
    user = get_user_by_login(login)
    
    if not user:
        record_failed_attempt(ip)
        return jsonify({"success": False, "message": "Пользователь не найден"})
    
    if not bcrypt.checkpw(password.encode(), user[2]):
        record_failed_attempt(ip)
        return jsonify({"success": False, "message": "Неверный пароль"})
    
    reset_attempts(ip)
    
    token = jwt.encode(
        {
            "user_id": user[0],
            "username": user[1],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
        },
        SECRET_KEY,
        algorithm="HS256"
    )
    
    return jsonify({
        "success": True,
        "token": token,
        "user": {
            "id": user[0],
            "username": user[1],
            "display_name": user[3],
            "email": user[4]
        }
    })

# ---- ВОССТАНОВЛЕНИЕ ПАРОЛЯ ----
@app.route('/api/recover', methods=['POST'])
def recover_password():
    data = request.json
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({"success": False, "message": "Введите email"})
    
    user = get_user_by_email(email)
    if not user:
        return jsonify({"success": False, "message": "Пользователь с таким email не найден"})
    
    return jsonify({
        "success": True,
        "message": "Код для сброса пароля: 123456",
        "code": "123456"
    })

# ---- ВСЕ ПОЛЬЗОВАТЕЛИ ----
@app.route('/api/users', methods=['GET'])
def get_users():
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    users = cursor.execute(
        "SELECT username, display_name, email FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    
    result = []
    for u in users:
        result.append({
            "username": u[0],
            "display_name": u[1],
            "email": u[2]
        })
    return jsonify(result)

# ---- ПОСТЫ ----
@app.route('/api/posts', methods=['GET'])
def get_posts():
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    posts = cursor.execute('''
        SELECT users.username, users.display_name, posts.text, posts.mood, posts.media, posts.time, posts.id
        FROM posts 
        JOIN users ON posts.user_id = users.id 
        ORDER BY posts.time DESC
    ''').fetchall()
    conn.close()
    
    result = []
    for p in posts:
        result.append({
            "username": p[0],
            "display_name": p[1],
            "text": p[2],
            "mood": p[3] or '·',
            "media": json.loads(p[4]) if p[4] else [],
            "time": p[5],
            "id": p[6],
            "likes": 0
        })
    return jsonify(result)

# ---- СОЗДАТЬ ПОСТ ----
@app.route('/api/posts', methods=['POST'])
def create_post():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"success": False, "message": "Не авторизован"})
    
    token = token.replace('Bearer ', '')
    user = get_user_by_token(token)
    if not user:
        return jsonify({"success": False, "message": "Неверный токен"})
    
    data = request.json
    text = data.get('text', '')
    mood = data.get('mood', '·')
    
    if not text:
        return jsonify({"success": False, "message": "Напишите что-нибудь"})
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO posts (user_id, text, mood) VALUES (?, ?, ?)",
        [user[0], text, mood]
    )
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Пост опубликован"})

# ---- УДАЛИТЬ ПОСТ ----
@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"success": False, "message": "Не авторизован"})
    
    token = token.replace('Bearer ', '')
    user = get_user_by_token(token)
    if not user:
        return jsonify({"success": False, "message": "Неверный токен"})
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    post = cursor.execute("SELECT user_id FROM posts WHERE id = ?", [post_id]).fetchone()
    
    if not post or post[0] != user[0]:
        conn.close()
        return jsonify({"success": False, "message": "Нельзя удалить чужой пост"})
    
    cursor.execute("DELETE FROM posts WHERE id = ?", [post_id])
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Пост удалён"})

# ---- ЛАЙКИ ----
@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
def like_post(post_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"success": False, "message": "Не авторизован"})
    
    token = token.replace('Bearer ', '')
    user = get_user_by_token(token)
    if not user:
        return jsonify({"success": False, "message": "Неверный токен"})
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    
    existing = cursor.execute(
        "SELECT * FROM likes WHERE post_id = ? AND user_id = ?",
        [post_id, user[0]]
    ).fetchone()
    
    if existing:
        cursor.execute(
            "DELETE FROM likes WHERE post_id = ? AND user_id = ?",
            [post_id, user[0]]
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "liked": False})
    else:
        cursor.execute(
            "INSERT INTO likes (post_id, user_id) VALUES (?, ?)",
            [post_id, user[0]]
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "liked": True})

# ---- ЧАТЫ ----
@app.route('/api/chats', methods=['GET'])
def get_chats():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"success": False, "message": "Не авторизован"})
    
    token = token.replace('Bearer ', '')
    user = get_user_by_token(token)
    if not user:
        return jsonify({"success": False, "message": "Неверный токен"})
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT DISTINCT 
            CASE 
                WHEN from_user = ? THEN to_user
                ELSE from_user
            END
        FROM messages
        WHERE from_user = ? OR to_user = ?
    ''', [user[1], user[1], user[1]])
    
    partners = cursor.fetchall()
    result = []
    
    for p in partners:
        partner = p[0]
        
        last = cursor.execute('''
            SELECT text, time FROM messages 
            WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)
            ORDER BY time DESC LIMIT 1
        ''', [user[1], partner, partner, user[1]]).fetchone()
        
        unread = cursor.execute('''
            SELECT COUNT(*) FROM messages 
            WHERE from_user = ? AND to_user = ? AND read = 0
        ''', [partner, user[1]]).fetchone()[0]
        
        result.append({
            "username": partner,
            "last_message": last[0] if last else '',
            "last_time": last[1] if last else None,
            "unread": unread
        })
    
    conn.close()
    return jsonify(result)

# ---- ОТПРАВИТЬ СООБЩЕНИЕ ----
@app.route('/api/messages', methods=['POST'])
def send_message():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"success": False, "message": "Не авторизован"})
    
    token = token.replace('Bearer ', '')
    user = get_user_by_token(token)
    if not user:
        return jsonify({"success": False, "message": "Неверный токен"})
    
    data = request.json
    to_user = data.get('to_user', '').strip().lower()
    text = data.get('text', '').strip()
    
    if not to_user or not text:
        return jsonify({"success": False, "message": "Заполните все поля"})
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO messages (from_user, to_user, text) VALUES (?, ?, ?)",
        [user[1], to_user, text]
    )
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Сообщение отправлено"})

# ---- ПОЛУЧИТЬ СООБЩЕНИЯ ----
@app.route('/api/messages/<username>', methods=['GET'])
def get_messages(username):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"success": False, "message": "Не авторизован"})
    
    token = token.replace('Bearer ', '')
    user = get_user_by_token(token)
    if not user:
        return jsonify({"success": False, "message": "Неверный токен"})
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    messages = cursor.execute('''
        SELECT from_user, to_user, text, time
        FROM messages
        WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)
        ORDER BY time ASC
    ''', [user[1], username, username, user[1]]).fetchall()
    conn.close()
    
    result = []
    for m in messages:
        result.append({
            "from": m[0],
            "to": m[1],
            "text": m[2],
            "time": m[3]
        })
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE messages SET read = 1 WHERE from_user = ? AND to_user = ?",
        [username, user[1]]
    )
    conn.commit()
    conn.close()
    
    return jsonify(result)

# ---- ГОЛОСОВЫЕ ----
@app.route('/api/voice', methods=['POST'])
def send_voice():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"success": False, "message": "Не авторизован"})
    
    token = token.replace('Bearer ', '')
    user = get_user_by_token(token)
    if not user:
        return jsonify({"success": False, "message": "Неверный токен"})
    
    data = request.json
    to_user = data.get('to_user', '').strip().lower()
    audio = data.get('audio', '')
    
    if not to_user or not audio:
        return jsonify({"success": False, "message": "Заполните все поля"})
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO messages (from_user, to_user, text) VALUES (?, ?, ?)",
        [user[1], to_user, "🎤 Голосовое сообщение"]
    )
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Голосовое отправлено"})

# ---- СОСТОЯНИЕ ----
@app.route('/api/mood', methods=['POST'])
def save_mood():
    data = request.json
    username = data.get('username', '').strip().lower()
    mood = data.get('mood', '')
    
    if not username or not mood:
        return jsonify({"success": False, "message": "Заполните все поля"})
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO moods (username, mood, date) VALUES (?, ?, DATE('now'))",
        [username, mood]
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Состояние сохранено"})

@app.route('/api/mood/<username>', methods=['GET'])
def get_mood(username):
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    mood = cursor.execute(
        "SELECT mood FROM moods WHERE username = ? AND date = DATE('now')",
        [username]
    ).fetchone()
    conn.close()
    return jsonify({"mood": mood[0] if mood else None})

# ---- БЛАГОДАРНОСТЬ ----
@app.route('/api/gratitude', methods=['POST'])
def save_gratitude():
    data = request.json
    username = data.get('username', '').strip().lower()
    text = data.get('text', '').strip()
    
    if not username or not text:
        return jsonify({"success": False, "message": "Заполните все поля"})
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO gratitude (username, text) VALUES (?, ?)",
        [username, text]
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Благодарность сохранена"})

@app.route('/api/gratitude/<username>', methods=['GET'])
def get_gratitude(username):
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    entries = cursor.execute(
        "SELECT text, date FROM gratitude WHERE username = ? ORDER BY date DESC LIMIT 10",
        [username]
    ).fetchall()
    conn.close()
    return jsonify([{"text": e[0], "date": e[1]} for e in entries])

# ---- ПОИСК ----
@app.route('/api/search', methods=['GET'])
def search_users():
    query = request.args.get('q', '').strip().lower()
    if not query:
        return jsonify([])
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    users = cursor.execute(
        "SELECT username, display_name, email FROM users WHERE username LIKE ? OR display_name LIKE ? LIMIT 10",
        [f'%{query}%', f'%{query}%']
    ).fetchall()
    conn.close()
    
    result = []
    for u in users:
        result.append({
            "username": u[0],
            "display_name": u[1],
            "email": u[2]
        })
    return jsonify(result)

# ---- ТЕКУЩИЙ ПОЛЬЗОВАТЕЛЬ ----
@app.route('/api/me', methods=['GET'])
def get_me():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Не авторизован"}), 401
    
    token = token.replace('Bearer ', '')
    user = get_user_by_token(token)
    if not user:
        return jsonify({"error": "Неверный токен"}), 401
    
    return jsonify({
        "id": user[0],
        "username": user[1],
        "display_name": user[2],
        "email": user[3]
    })

# ---- ЗАПУСК ----
if __name__ == '__main__':
    init_db()
    print("🚀 Сервер запущен на http://localhost:5000")
    print("📡 API доступны по адресу http://localhost:5000/api/...")
    print("👤 Тестовые пользователи: alex/alex123, marina/marina123")
    print("🎤 Голосовые сообщения работают!")
    app.run(host='0.0.0.0', port=5000)