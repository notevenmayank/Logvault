import sqlite3
import os
from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


init_db()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@auth_bp.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    existing = cursor.fetchone()
    if existing:
        conn.close()
        return jsonify({"success": False, "error": "Email already registered"}), 409

    pwd_hash = generate_password_hash(password)
    try:
        cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pwd_hash))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"success": False, "error": "Email already registered"}), 409

    session["user_id"] = user_id
    session["email"] = email
    return jsonify({"success": True, "email": email}), 200


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"success": False, "error": "Invalid email or password"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "error": "Invalid email or password"}), 401

    session["user_id"] = user["id"]
    session["email"] = user["email"]
    return jsonify({"success": True, "email": user["email"]}), 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True}), 200


@auth_bp.route("/me", methods=["GET"])
def me():
    email = session.get("email")
    if email:
        return jsonify({"authenticated": True, "email": email}), 200
    return jsonify({"authenticated": False}), 200
