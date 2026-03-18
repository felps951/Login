from flask import Flask, render_template, request, redirect, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import time
import os


app = Flask(__name__)
app.secret_key = "segredo_super_secreto"

# Criar banco
def criar_banco():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario TEXT,
        senha TEXT
    )
    """)

    conn.commit()
    conn.close()


criar_banco()


# Criar usuário padrão
def criar_usuario_padrao():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    senha_hash = generate_password_hash("senha@@123")

    cursor.execute("SELECT * FROM usuarios WHERE usuario = ?", ("Fellipe",))
    if not cursor.fetchone():
        cursor.execute("INSERT INTO usuarios (usuario, senha) VALUES (?, ?)", ("Fellipe", senha_hash))

    conn.commit()
    conn.close()


criar_usuario_padrao()


# Rota login
@app.route("/", methods=["GET", "POST"])
def login():

    if "tentativas" not in session:
        session["tentativas"] = 0

    if "bloqueado_ate" in session:
        if time.time() < session["bloqueado_ate"]:
            return render_template("login.html", erro="Aguarde 1 minuto para tentar novamente")

    if request.method == "POST":
        usuario = request.form["usuario"]
        senha = request.form["senha"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], senha):
            session["usuario"] = usuario
            session["tentativas"] = 0
            return redirect("/dashboard")
        else:
            session["tentativas"] += 1

            if session["tentativas"] >= 3:
                session["bloqueado_ate"] = time.time() + 60
                session["tentativas"] = 0
                return render_template("login.html", erro="Bloqueado por 1 minuto!")

            return render_template("login.html", erro=f"Tentativa {session['tentativas']} de 3")

    return render_template("login.html")

# Cadastro
@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        usuario = request.form["usuario"]
        senha = generate_password_hash(request.form["senha"])

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute("INSERT INTO usuarios (usuario, senha) VALUES (?, ?)", (usuario, senha))

        conn.commit()
        conn.close()

        return redirect("/")

    return render_template("cadastro.html")


# Dashboard (protegido)
@app.route("/dashboard")
def dashboard():
    if "usuario" not in session:
        return redirect("/")

    return render_template("dashboard.html", usuario=session["usuario"])


# Logout
@app.route("/logout")
def logout():
    session.pop("usuario", None)
    return redirect("/")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
