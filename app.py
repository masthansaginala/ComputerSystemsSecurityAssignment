from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message, Mail
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from dotenv import load_dotenv
from flask_socketio import SocketIO, join_room, leave_room, emit
import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
    NoEncryption
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')
s = URLSafeTimedSerializer(app.secret_key)
socketio = SocketIO(app)

# Configuration for Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

# Configuration for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Instantiate SQLAlchemy, Migrate, and JWTManager
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Diffie-Hellman key exchange parameters
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    active = db.Column(db.Boolean, default=False)

# Temporary in-app storage for public keys and chat requests
public_keys = {}
chat_requests = {}

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
            return redirect(url_for('chat'))
        else:
            flash('Invalid email or password, or account not activated', 'error')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('email', None)
    session.pop('private_key', None)
    session.pop('aes_key', None)
    flash('You are logged out. Please log in again to use our services.')
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
        join_room(email)
        if email in chat_requests:
            for request in chat_requests[email]:
                socketio.emit('chat_request_received', {'sender': request['sender'], 'public_key': request['public_key']}, room=email)

@socketio.on('start_chat')
def handle_start_chat(data):
    sender_email = session['email']
    recipient_email = data['recipient']

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    session['private_key'] = private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption()
    )
    public_key_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    public_keys[sender_email] = b64encode(public_key_pem).decode('utf-8')

    recipient_user = User.query.filter_by(email=recipient_email).first()
    if recipient_user:
        msg = Message('Public Key Exchange', sender=app.config['MAIL_USERNAME'], recipients=[recipient_email])
        msg.body = f'Public key from {sender_email}: {public_keys[sender_email]}'
        mail.send(msg)
        
        if recipient_email not in chat_requests:
            chat_requests[recipient_email] = []
        chat_requests[recipient_email].append({'sender': sender_email, 'public_key': public_keys[sender_email]})
        
        emit('chat_request_sent', {'status': 'Chat request sent', 'public_key': public_keys[sender_email]}, room=sender_email)
    else:
        emit('error', {'message': 'Recipient not found'}, room=sender_email)

@socketio.on('accept_chat')
def handle_accept_chat(data):
    recipient_email = session['email']
    sender_email = data['sender']
    sender_public_key = data['public_key']
    
    
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    session['private_key'] = private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption()
    )
    public_key_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    public_keys[recipient_email] = b64encode(public_key_pem).decode('utf-8')
    
    
    sender_user = User.query.filter_by(email=sender_email).first()
    if sender_user:
        msg = Message('Public Key Exchange', sender=app.config['MAIL_USERNAME'], recipients=[sender_email])
        msg.body = f'Public key from {recipient_email}: {public_keys[recipient_email]}'
        mail.send(msg)
        emit('chat_request_accepted', {'recipient': recipient_email, 'public_key': public_keys[recipient_email]}, room=sender_email)
        
        
        socketio.emit('exchange_keys', {'other_user': recipient_email, 'public_key': public_keys[recipient_email]}, room=sender_email)
        socketio.emit('exchange_keys', {'other_user': sender_email, 'public_key': sender_public_key}, room=recipient_email)
    else:
        emit('error', {'message': 'Sender not found'}, room=recipient_email)
@socketio.on('exchange_keys')
def handle_exchange_keys(data):
    email = session['email']
    other_user = data['other_user']
    other_public_key_pem = b64decode(data['public_key'])
    
    other_public_key = load_pem_public_key(other_public_key_pem, backend=default_backend())
    
    # Load private key from session
    private_key_pem = session.get('private_key')
    if not private_key_pem:
        emit('error', {'message': 'Private key not found'}, room=email)
        return
    
    private_key = load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    # Generate shared secret
    shared_key = private_key.exchange(other_public_key)
    
    # Derive AES key from shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    
    session['aes_key'] = derived_key
    
    emit('keys_exchanged', {'status': 'Keys exchanged successfully'}, room=email)

@socketio.on('send_message')
def handle_send_message(data):
    message = data['message']
    recipient = data['recipient']
    
    # Encrypt message with AES key
    aes_key = session.get('aes_key')
    if not aes_key:
        emit('error', {'message': 'AES key not found'}, room=session['email'])
        return
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    encrypted_message = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
    
    # Send the encrypted message to the recipient
    socketio.emit('receive_message', {
        'sender': session['email'],
        'nonce': b64encode(nonce).decode('utf-8'),
        'encrypted_message': b64encode(encrypted_message).decode('utf-8')
    }, room=recipient)

@socketio.on('receive_message')
def handle_receive_message(data):
    encrypted_message = b64decode(data['encrypted_message'])
    nonce = b64decode(data['nonce'])
    
    # Decrypt message with AES key
    aes_key = session.get('aes_key')
    if not aes_key:
        emit('error', {'message': 'AES key not found'}, room=session['email'])
        return
    aesgcm = AESGCM(aes_key)
    decrypted_message = aesgcm.decrypt(nonce, encrypted_message, None)
    
    # Emit the decrypted message to the user
    socketio.emit('message', {'message': decrypted_message.decode('utf-8'), 'sender': data['sender']}, room=session['email'])

if __name__ == '__main__':
    socketio.run(app, debug=True)
