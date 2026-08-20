from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import bcrypt
import jwt
import datetime
import os

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

SECRET_KEY = "spokum_secret_2026"

def init_db():
    if os.path.exists('social.db'):
        os.remove('social.db')
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            text TEXT,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ База данных создана!")

def get_user_by_token(token):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        conn = sqlite3.connect('social.db')
        cursor = conn.cursor()
        user = cursor.execute(
            "SELECT id, username, display_name FROM users WHERE id = ?",
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
        "SELECT id, username, password_hash, display_name FROM users WHERE username = ?",
        [username]
    ).fetchone()
    conn.close()
    return user

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    display_name = data.get('display_name', username)
    email = data.get('email', '')
    
    if not username or not password:
        return jsonify({"success": False, "message": "Заполните все поля"})
    
    if len(password) < 8:
        return jsonify({"success": False, "message": "Пароль минимум 8 символов"})
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    
    try:
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (username, password_hash, display_name, email) VALUES (?, ?, ?, ?)",
            [username, password_hash, display_name, email or '']
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Регистрация успешна!"})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"success": False, "message": "Пользователь уже существует"})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('login', '').strip().lower()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({"success": False, "message": "Заполните все поля"})
    
    user = get_user_by_username(username)
    
    if not user:
        return jsonify({"success": False, "message": "Пользователь не найден"})
    
    if not bcrypt.checkpw(password.encode(), user[2]):
        return jsonify({"success": False, "message": "Неверный пароль"})
    
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
            "display_name": user[3]
        }
    })

@app.route('/api/posts', methods=['GET'])
def get_posts():
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    posts = cursor.execute('''
        SELECT users.username, users.display_name, posts.text, posts.time, posts.id
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
            "time": p[3],
            "id": p[4],
            "likes": 0
        })
    return jsonify(result)

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
    
    if not text:
        return jsonify({"success": False, "message": "Напишите что-нибудь"})
    
    conn = sqlite3.connect('social.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO posts (user_id, text) VALUES (?, ?)",
        [user[0], text]
    )
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Пост опубликован"})

if __name__ == '__main__':
    init_db()
    print("🚀 Сервер запущен на http://localhost:5000")
    print("📡 API доступны по адресу http://localhost:5000/api/...")
    app.run(host='0.0.0.0', port=5000)
