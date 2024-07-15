from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message, Mail
import psycopg2
from psycopg2 import sql
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)
app.secret_key = '886276ab36dc7e16d549119e1f811852'  # Replace with your actual secret key
s = URLSafeTimedSerializer(app.secret_key)

# Configuration for Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)


# PostgreSQL connection details
db_config = {
    'host': 'localhost',  # Assuming PostgreSQL is running on the same machine
    'dbname': '',  # Replace with your PostgreSQL database name
    'user': 'postgres',  # Replace with your PostgreSQL username
    'password': ''  # Replace with your PostgreSQL password
}

def get_db_connection():
    conn = psycopg2.connect(**db_config)
    return conn

# Setup PostgreSQL database
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            active BOOLEAN NOT NULL DEFAULT FALSE
        )
    ''')
    conn.commit()
    cursor.close()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        password = generate_password_hash(password)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, password, active) VALUES (%s, %s, %s)", (email, password, False))
        conn.commit()
        cursor.close()
        conn.close()
        token = s.dumps(email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)


        msg = Message('Confirm Your Account', sender = app.config['MAIL_USERNAME'], recipients = [email])
        msg.body = f'This is your activation link {link}'
        mail.send(msg)
        flash('A confirmation email has been sent via email.', 'success')
        
        return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET active = TRUE WHERE email = %s", (email,))
    conn.commit()
    cursor.close()
    conn.close()

    flash('Your account has been activated!', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            return redirect(url_for('chat'))
        else:
            flash('Invalid email or password','error')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('login'))
    return render_template('chat.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    flash('you are logged out please login again to have our services')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
