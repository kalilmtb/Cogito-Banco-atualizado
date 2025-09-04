from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Altere para uma chave segura em produção

# Função para criar as tabelas no banco de dados
def init_db():
    # Conexão com o banco de login
    conn_login = sqlite3.connect('login.db')
    cursor_login = conn_login.cursor()
    cursor_login.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL
        )
    ''')
    conn_login.commit()
    conn_login.close()
    
    # Conexão com o banco de perfil
    conn_perfil = sqlite3.connect('perfil.db')
    cursor_perfil = conn_perfil.cursor()
    cursor_perfil.execute('''
        CREATE TABLE IF NOT EXISTS perfis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            escolaridade TEXT NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    ''')
    conn_perfil.commit()
    conn_perfil.close()

# Função para hash de senha
def hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['user']
        senha = request.form['pass']
        senha_hash = hash_senha(senha)
        
        # Verificar credenciais no banco de dados
        conn = sqlite3.connect('login.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM usuarios WHERE email = ? AND senha = ?', (email, senha_hash))
        usuario = cursor.fetchone()
        conn.close()
        
        if usuario:
            session['usuario_id'] = usuario[0]
            session['email'] = usuario[1]
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Email ou senha incorretos!', 'danger')
    
    return render_template('login.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        confirmar_email = request.form['confirm-email']
        senha = request.form['password']
        confirmar_senha = request.form['confirm-password']
        escolaridade = request.form['escolaridade']
        
        # Verificar se os emails coincidem
        if email != confirmar_email:
            flash('Os emails não coincidem!', 'danger')
            return render_template('cadastro.html')
        
        # Verificar se as senhas coincidem
        if senha != confirmar_senha:
            flash('As senhas não coincidem!', 'danger')
            return render_template('cadastro.html')
        
        # Hash da senha
        senha_hash = hash_senha(senha)
        
        try:
            # Inserir no banco de login
            conn_login = sqlite3.connect('login.db')
            cursor_login = conn_login.cursor()
            cursor_login.execute('INSERT INTO usuarios (email, senha) VALUES (?, ?)', (email, senha_hash))
            usuario_id = cursor_login.lastrowid
            conn_login.commit()
            conn_login.close()
            
            # Inserir no banco de perfil
            conn_perfil = sqlite3.connect('perfil.db')
            cursor_perfil = conn_perfil.cursor()
            cursor_perfil.execute('INSERT INTO perfis (usuario_id, username, email, escolaridade) VALUES (?, ?, ?, ?)', 
                                 (usuario_id, username, email, escolaridade))
            conn_perfil.commit()
            conn_perfil.close()
            
            flash('Cadastro realizado com sucesso! Faça login para continuar.', 'success')
            return redirect(url_for('login'))
            
        except sqlite3.IntegrityError:
            flash('Este email já está cadastrado!', 'danger')
    
    return render_template('cadastro.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)