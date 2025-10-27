from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secret123"

DB_NAME = "users.db"

# ------------------- Veritabanı -------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ------------------- Admin oluştur -------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # Buraya kendi şifreni koy

def ensure_admin_exists():
    hashed = generate_password_hash(ADMIN_PASSWORD)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username=?", (ADMIN_USERNAME,))
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (ADMIN_USERNAME, hashed))
        conn.commit()
    conn.close()

ensure_admin_exists()

# ------------------- Şifre kuralları -------------------
def validate_password(password):
    if len(password) < 3 or len(password) > 21:
        return False, "Şifre 3-21 karakter arasında olmalı."
    if not re.search(r"[A-Z]", password):
        return False, "Şifre en az 1 büyük harf içermeli."
    if not re.search(r"[a-z]", password):
        return False, "Şifre en az 1 küçük harf içermeli."
    return True, ""

# ------------------- Kayıt -------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        valid, message = validate_password(password)
        if not valid:
            return message

        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return "Bu kullanıcı adı zaten var!"
        finally:
            conn.close()
    return render_template("register.html")

# ------------------- Giriş -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            session["user"] = username
            return redirect(url_for("home"))
        else:
            return "Hatalı kullanıcı adı veya şifre!"
    return render_template("login.html")

# ------------------- Ana sayfa -------------------
@app.route("/home")
def home():
    if "user" in session:
        return render_template("home.html", user=session["user"])
    return redirect(url_for("login"))

# ------------------- Çıkış -------------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# ------------------- Admin Paneli -------------------
@app.route("/admin")
def admin_panel():
    if "user" not in session or session["user"] != "admin":
        return "Erişim reddedildi! Admin girişi yapmalısınız."

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users")
    users = cursor.fetchall()
    conn.close()
    return render_template("admin.html", users=users)

# ------------------- Çalıştır -------------------
if __name__ == "__main__":
    app.run(debug=True)
