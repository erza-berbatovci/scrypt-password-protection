import os
import hashlib
import base64
import hmac
import pyodbc
from flask import Flask, render_template, request, redirect, url_for, flash

# Config
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64
SALT_LEN = 16

DB_SERVER = r'localhost\MSSQLSERVER02'
DB_NAME = 'ScryptDB'
DB_DRIVER = '{ODBC Driver 17 for SQL Server}'
CONN_STR = f'DRIVER={DB_DRIVER};SERVER={DB_SERVER};DATABASE={DB_NAME};Trusted_Connection=yes;'

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ---------- DB helpers ----------
def init_db():
    conn = pyodbc.connect(CONN_STR)
    cursor = conn.cursor()
    cursor.execute('''
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Users' AND xtype='U')
        CREATE TABLE Users (
            Id INT IDENTITY(1,1) PRIMARY KEY,
            Username NVARCHAR(100) UNIQUE NOT NULL,
            PasswordHash NVARCHAR(MAX) NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def save_user(username: str, password_hash: str):
    conn = pyodbc.connect(CONN_STR)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO Users (Username, PasswordHash) VALUES (?, ?)', (username, password_hash))
    conn.commit()
    conn.close()


def get_user(username: str):
    conn = pyodbc.connect(CONN_STR)
    cursor = conn.cursor()
    cursor.execute('SELECT Id, Username, PasswordHash FROM Users WHERE Username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    return row


def list_users():
    conn = pyodbc.connect(CONN_STR)
    cursor = conn.cursor()
    cursor.execute('SELECT Id, Username FROM Users ORDER BY Id')
    rows = cursor.fetchall()
    conn.close()
    return rows

# ---------- scrypt helpers ----------
def create_password_hash(password: str) -> str:
    salt = os.urandom(SALT_LEN)
    key = hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN
    )
    # ruaj: base64(salt + key)
    stored = base64.b64encode(salt + key).decode('utf-8')
    return stored

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        data = base64.b64decode(stored_hash.encode('utf-8'))
    except Exception:
        return False
    salt = data[:SALT_LEN]
    key_stored = data[SALT_LEN:]
    try:
        key_test = hashlib.scrypt(
            password.encode('utf-8'),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=len(key_stored)
        )
    except Exception:
        return False
    # përdor compare_digest (ose hmac.compare_digest) për krahasim të sigurt
    return hmac.compare_digest(key_test, key_stored)

# ---------- Routes ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Ploteso username dhe password.', 'warning')
            return redirect(url_for('register'))

        if get_user(username):
            flash('Username ekziston - zgjedh nje tjeter.', 'danger')
            return redirect(url_for('register'))

        password_hash = create_password_hash(password)
        save_user(username, password_hash)
        flash('Regjistrim i suksesshëm. Mund të logohesh tani.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = get_user(username)
        if not user:
            flash('Përdoruesi nuk u gjet.', 'danger')
            return redirect(url_for('login'))

        _, _, stored_hash = user
        if verify_password(password, stored_hash):
            flash(f'✅ Sukses! Ju jeni kyçur si {username}.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Fjalëkalim i pasaktë.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/users')
def users():
    rows = list_users()
    return render_template('users.html', users=rows)

# ---------- Startup ----------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
