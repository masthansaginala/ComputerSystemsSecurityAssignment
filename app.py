# from flask import Flask
# from flask_sqlalchemy import SQLALchemy
# from flask_mail import Mail
# import urllib.parse


# # email and Database (we are using postgresql)
# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'your_secret_key'
# app.config['SQLALCHEMY_DATABASE_URL'] = 'postgresql://username:password@host:port/database'
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
# app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')



from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
import psycopg2
from psycopg2 import sql
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)
app.secret_key = '886276ab36dc7e16d549119e1f811852'  # Replace with your actual secret key

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
    'dbname': ' ',  # Replace with your PostgreSQL database name
    'user': 'postgres',  # Replace with your PostgreSQL username
    'password': ' 1'  # Replace with your PostgreSQL password
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

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, password, active) VALUES (%s, %s, %s)", (email, password, False))
        conn.commit()
        cursor.close()
        conn.close()

        
        return redirect(url_for('index'))

    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)
