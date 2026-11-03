import os
import hmac
import hashlib
import mysql.connector
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

DB_CONFIG = {
    "host": "185.114.247.43",
    "port": 3306,
    "database": "sch688_vvedenie",
    "user": "sch688_vvedenie",
    "password": "Qwerty123",
}

ITERATIONS = 100_000
SALT_LEN = 16
HASH_LEN = 32


def hash_password(password: str) -> str:
    salt = os.urandom(SALT_LEN)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=HASH_LEN)
    return salt.hex() + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    if not stored or len(stored) < SALT_LEN * 2:
        return False
    try:
        salt = bytes.fromhex(stored[:SALT_LEN * 2])
        expected_bytes = bytes.fromhex(stored[SALT_LEN * 2:])
    except (ValueError, TypeError):
        return False

    if len(expected_bytes) != HASH_LEN:
        return False

    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=HASH_LEN)
    return hmac.compare_digest(dk, expected_bytes)


@app.route('/user_register', methods=['POST'])
def user_register():
    req = request.get_json(silent=True) or {}
    name = (req.get('name') or req.get('fullname') or '').strip()
    email = (req.get('email') or '').strip().lower()
    password = req.get('password') or ''

    if not name or not email or not password:
        return jsonify({"result": False, "message": "Заполните все поля"}), 400

    cnx = mysql.connector.connect(**DB_CONFIG)
    cur = cnx.cursor(dictionary=True)
    try:
        cur.execute('SELECT id FROM `users` WHERE `email` = %s', (email,))
        if cur.fetchone() is not None:
            return jsonify({"result": False, "message": "Пользователь с таким email уже существует"}), 409

        password_hash = hash_password(password)

        cur.execute(
            'INSERT INTO `users`(`username`, `email`, `password_hash`) VALUES (%s, %s, %s)',
            (name, email, password_hash)
        )
        cnx.commit()
        new_id = cur.lastrowid
        return jsonify({"result": True, "id": new_id, "redirect": url_for('login')}), 200
    except mysql.connector.Error as e:
        cnx.rollback()
        return jsonify({"result": False, "message": f"Ошибка БД: {e}"}), 500
    finally:
        cur.close()
        cnx.close()


@app.route('/user_login', methods=['POST'])
def user_login():
    req = request.get_json(silent=True) or {}
    email = (req.get('email') or '').strip().lower()
    password = req.get('password') or ''

    if not email or not password:
        return jsonify({"status": "error", "message": "Заполните все поля"}), 400

    cnx = mysql.connector.connect(**DB_CONFIG)
    cur = cnx.cursor(dictionary=True)
    try:
        cur.execute(
            'SELECT id, username, email, password_hash FROM `users` WHERE `email` = %s',
            (email,)
        )
        user = cur.fetchone()
    finally:
        cur.close()
        cnx.close()

    if user is None:
        return jsonify({"status": "error", "message": "Пользователь не найден"}), 404

    if not verify_password(password, user['password_hash']):
        return jsonify({"status": "error", "message": "Неверный пароль"}), 401

    session['user_id'] = user['id']
    session['username'] = user['username']
    session['email'] = user['email']

    return jsonify({
        "status": "ok",
        "message": "Успешный вход",
        "redirect": url_for('profile'),
        "user": {"id": user["id"], "username": user["username"], "email": user["email"]}
    }), 200


@app.route('/user_logout', methods=['POST'])
def user_logout():
    session.clear()
    return jsonify({"status": "ok", "redirect": url_for('login')}), 200


@app.route("/profile")
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    balance = 0.0
    cnx = None
    cur = None
    try:
        cnx = mysql.connector.connect(**DB_CONFIG)
        cur = cnx.cursor(dictionary=True)
        cur.execute('SELECT balance FROM `users` WHERE id = %s', (session['user_id'],))
        db_user = cur.fetchone()
        if db_user and db_user.get('balance') is not None:
            balance = float(db_user['balance'])
    except Exception as e:
        print(f"!!! ОШИБКА ПРИ ПОЛУЧЕНИИ БАЛАНСА: {e}")
        # Если произошла ошибка (например, нет колонки balance), баланс останется 0.0
    finally:
        if cur: cur.close()
        if cnx: cnx.close()

    return render_template(
        'profile.html',
        username=session.get('username'),
        email=session.get('email'),
        user_id=session.get('user_id'),
        balance=balance
    )


@app.route("/")
def registration():
    return render_template('registration.html')


@app.route("/login")
def login():
    return render_template('login.html')


if __name__ == "__main__":
    app.run(debug=True)