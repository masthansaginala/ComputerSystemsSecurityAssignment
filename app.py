from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message, Mail
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import os
from dotenv import load_dotenv
from flask_socketio import SocketIO, join_room
# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = '886276ab36dc7e16d549119e1f811852'  # Replace with your actual secret key
s = URLSafeTimedSerializer(app.secret_key)

# Configuration for Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'masthansaginala163@gmail.com'
app.config['MAIL_PASSWORD'] = 'ztoygjlqwalhfibh'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

# Configuration for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin123@localhost:5432/chatapplication'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Instantiate SQLAlchemy, Migrate, and JWTManager
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    active = db.Column(db.Boolean, default=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        password = generate_password_hash(password)

        new_user = User(email=email, password=password, active=False)
        db.session.add(new_user)
        db.session.commit()

        token = s.dumps(email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)

        msg = Message('Confirm Your Account', sender=app.config['MAIL_USERNAME'], recipients=[email])
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

    user = User.query.filter_by(email=email).first()
    if user:
        user.active = True
        db.session.commit()

    flash('Your account has been activated!', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password) and user.active:
            flash('Login successful!', 'success')
            session['email'] = email
            return render_template('chat.html')
        else:
            flash('Invalid email or password, or account not activated', 'error')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('email', None)
    flash('you are logged out please login again to have our services')
    return redirect(url_for('index'))

@app.route('/chat')
def chat():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html')

@socketio.on('connect')
def handle_connect():
    email = session.get('email')
    if email:
        join_room(email)g
        

if __name__ == '__main__':
    app.run(debug=True)
