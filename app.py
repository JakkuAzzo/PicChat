from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
import sqlite3
import os
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin, current_user
from stegano import lsb
from werkzeug.utils import secure_filename
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key'
csrf = CSRFProtect(app)
app.config['WTF_CSRF_CHECK_DEFAULT'] = False
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'picchat.db'
IMAGES_FOLDER = 'images'
SCHEMA_FILE = 'schema.sql'

# Ensure the images folder exists
if not os.path.exists(IMAGES_FOLDER):
    os.makedirs(IMAGES_FOLDER)

app.config['UPLOAD_FOLDER'] = IMAGES_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# User model for Flask-Login
class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        user_obj = User()
        user_obj.id = user['id']
        user_obj.username = user['username']
        return user_obj
    return None

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_schema_file():
    schema_sql = """
    -- Drop existing tables if they exist
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS conversations;
    DROP TABLE IF EXISTS messages;

    -- Create users table
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );

    -- Create conversations table
    CREATE TABLE conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        contact TEXT NOT NULL,
        last_message_time TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );

    -- Create messages table
    CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        message_text TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (conversation_id) REFERENCES conversations (id),
        FOREIGN KEY (sender_id) REFERENCES users (id)
    );
    """
    with open(SCHEMA_FILE, 'w') as f:
        f.write(schema_sql)

def init_db():
    if not os.path.exists(SCHEMA_FILE):
        create_schema_file()
    with app.app_context():
        db = get_db_connection()
        with app.open_resource(SCHEMA_FILE, mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

init_db()

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            user_obj = User()
            user_obj.id = user['id']
            user_obj.username = user['username']
            login_user(user_obj)
            return redirect(url_for('chat'))
        else:
            flash('Invalid credentials')
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            conn.close()
            flash('Signup successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
            conn.close()
    return render_template('index.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    conn = get_db_connection()
    conversations = conn.execute('SELECT * FROM conversations WHERE user_id = ?', (current_user.id,)).fetchall()
    conn.close()
    return render_template('chat.html', conversations=conversations)

@app.route('/start_conversation', methods=['POST'])
@login_required
def start_conversation():
    data = request.get_json()
    contact = data.get('contact')
    conn = get_db_connection()
    # Check if the contact exists
    user = conn.execute('SELECT * FROM users WHERE username = ?', (contact,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'success': False, 'message': 'User does not exist.'})
    # Check if conversation already exists
    conversation = conn.execute('''
        SELECT * FROM conversations WHERE user_id = ? AND contact = ?
    ''', (current_user.id, contact)).fetchone()
    if conversation:
        conn.close()
        return jsonify({'success': True})
    # Create new conversation
    conn.execute('''
        INSERT INTO conversations (user_id, contact, last_message_time)
        VALUES (?, ?, ?)
    ''', (current_user.id, contact, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/chat_with/<contact>', methods=['GET', 'POST'])
@login_required
def chat_with(contact):
    conn = get_db_connection()
    conversation = conn.execute('''
        SELECT * FROM conversations WHERE user_id = ? AND contact = ?
    ''', (current_user.id, contact)).fetchone()
    if not conversation:
        flash('Conversation does not exist.')
        conn.close()
        return redirect(url_for('chat'))
    if request.method == 'POST':
        message_text = request.form['message']
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute('''
            INSERT INTO messages (conversation_id, sender_id, message_text, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (conversation['id'], current_user.id, message_text, timestamp))
        conn.commit()
        # Update last_message_time
        conn.execute('''
            UPDATE conversations SET last_message_time = ?
            WHERE id = ?
        ''', (timestamp, conversation['id']))
        conn.commit()
        # For AJAX response
        messages = conn.execute('''
            SELECT * FROM messages WHERE conversation_id = ? ORDER BY timestamp ASC
        ''', (conversation['id'],)).fetchall()
        messages_html = render_template('messages.html', messages=messages, contact=contact)
        conn.close()
        return jsonify({'messages_html': messages_html})
    messages = conn.execute('''
        SELECT * FROM messages WHERE conversation_id = ? ORDER BY timestamp ASC
    ''', (conversation['id'],)).fetchall()
    image_list = [f for f in os.listdir(IMAGES_FOLDER) if os.path.isfile(os.path.join(IMAGES_FOLDER, f))]
    background_image = random.choice(image_list) if image_list else None
    conn.close()
    return render_template('chat_with.html', contact=contact, messages=messages, background_image=background_image)

@app.route('/exit_chat/<contact>', methods=['GET', 'POST'])
@login_required
def exit_chat(contact):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        password = request.form['password']
        conn = get_db_connection()
        messages = conn.execute('''
            SELECT * FROM messages
            WHERE conversation_id = (SELECT id FROM conversations WHERE user_id = ? AND contact = ?)
            ORDER BY timestamp ASC
        ''', (session['user_id'], contact)).fetchall()
        conn.close()
        
        # Create a comma-separated list of messages
        message_list = [f"{msg['sender_id']},{msg['timestamp']},{msg['message_text']}" for msg in messages]
        message_text = "\n".join(message_list)
        
        # Encrypt the message text
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        encrypted_text = cipher_suite.encrypt(message_text.encode()).decode()
        
        # Embed in image
        image_name = embed_in_image(encrypted_text, session['user_id'])
        
        # Update conversation in DB
        conn = get_db_connection()
        conn.execute('''
            UPDATE conversations
            SET encrypted_messages = ?, encryption_key = ?, image_name = ?
            WHERE user_id = ? AND contact = ?
        ''', (encrypted_text, key.decode(), image_name, session['user_id'], contact))
        conn.commit()
        conn.close()
        
        flash('Messages encrypted and stored.')
        return redirect(url_for('chat'))
    return render_template('encrypt.html', contact=contact)

@app.route('/restore_chat/<contact>', methods=['GET', 'POST'])
@login_required
def restore_chat(contact):
    if request.method == 'POST':
        image_path = request.form['image_path']
        password = request.form['password']
        decrypted_text = decrypt_messages(image_path, password)
        # Convert the decrypted text back to messages and display them
        messages = []
        for line in decrypted_text.split('\n'):
            sender_id, timestamp, message_text = line.split(',')
            messages.append({'sender_id': sender_id, 'timestamp': timestamp, 'message_text': message_text})
        return render_template('chat_with.html', messages=messages, contact=contact)
    return render_template('restore_chat.html', contact=contact)

@app.route('/images/<path:filename>')
def images(filename):
    return send_from_directory(IMAGES_FOLDER, filename)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/search_users')
@login_required
def search_users():
    query = request.args.get('q', '')
    conn = get_db_connection()
    users = conn.execute('SELECT username FROM users WHERE username LIKE ?', ('%' + query + '%',)).fetchall()
    conn.close()
    return jsonify({'users': [dict(user) for user in users]})

if __name__ == '__main__':
    app.run(debug=True)