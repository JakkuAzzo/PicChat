from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import sqlite3
import os
import datetime
import random
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from PIL import Image
import io
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'picchat.db'
IMAGES_FOLDER = 'images'

# Ensure the images folder exists
if not os.path.exists(IMAGES_FOLDER):
    os.makedirs(IMAGES_FOLDER)

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # Create conversations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contact TEXT NOT NULL,
            last_message_time TEXT,
            encrypted_messages TEXT,
            encryption_key TEXT,
            image_name TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    # Create Messages Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            message_text TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(conversation_id) REFERENCES conversations(id),
            FOREIGN KEY(sender_id) REFERENCES users(id)
        )
    ''')
    # Create Passwords Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            password TEXT NOT NULL,
            FOREIGN KEY(conversation_id) REFERENCES conversations(id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Login logic
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('chat'))
        else:
            flash('Invalid credentials')
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Signup logic
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            conn.close()
            flash('Account created successfully! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
            conn.close()
    return render_template('index.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        # Clear messages and replace with conversation image
        conn = get_db_connection()
        conversations = conn.execute('SELECT * FROM conversations WHERE user_id = ?', (session['user_id'],)).fetchall()
        for conversation in conversations:
            messages = conn.execute('SELECT * FROM messages WHERE conversation_id = ?', (conversation['id'],)).fetchall()
            if messages:
                sorted_history = sorted(messages, key=lambda msg: (msg['sender_id'], msg['timestamp']))
                conversation_history = ','.join([f"{msg['sender_id']},{msg['timestamp']},{msg['message_text']}" for msg in sorted_history])
                encrypted_data = encrypt_conversation(conversation_history, 'default_password')
                user_folder = os.path.join(IMAGES_FOLDER, session['username'])
                if not os.path.exists(user_folder):
                    os.makedirs(user_folder)
                embed_in_image(encrypted_data, user_folder)
        conn.execute('DELETE FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE user_id = ?)', (session['user_id'],))
        conn.commit()
        conn.close()
    session.clear()
    return redirect(url_for('login'))

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    # Chat logic
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    conversations = conn.execute('SELECT * FROM conversations WHERE user_id = ?', (session['user_id'],)).fetchall()
    image_list = [f for f in os.listdir(IMAGES_FOLDER) if os.path.isfile(os.path.join(IMAGES_FOLDER, f))]
    background_image = random.choice(image_list) if image_list else None
    conn.close()
    return render_template('chat_with.html', conversations=conversations, contact=None, messages=None, background_image=background_image)

@app.route('/start_conversation', methods=['POST'])
def start_conversation():
    contact = request.form['contact']
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO conversations (user_id, contact, last_message_time)
        VALUES (?, ?, ?)
    ''', (session['user_id'], contact, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return redirect(url_for('chat_with', contact=contact))

@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')

@app.route('/chat_with/<contact>', methods=['GET', 'POST'])
def chat_with(contact):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conversation = conn.execute('SELECT * FROM conversations WHERE user_id = ? AND contact = ?', (session['user_id'], contact)).fetchone()
    messages = conn.execute('SELECT * FROM messages WHERE conversation_id = ?', (conversation['id'],)).fetchall()
    conn.close()
    
    if request.method == 'POST' and 'save_conversation' in request.form:
        password = request.form['password']
        # Retrieve and sort conversation history
        sorted_history = sorted(messages, key=lambda msg: (msg['sender_id'], msg['timestamp']))
        conversation_history = ','.join([f"{msg['sender_id']},{msg['timestamp']},{msg['message_text']}" for msg in sorted_history])
        # Encrypt the conversation
        encrypted_data = encrypt_conversation(conversation_history, password)
        # Embed encrypted data into an image
        user_folder = os.path.join(IMAGES_FOLDER, session['username'])
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)
        image_path = embed_in_image(encrypted_data, user_folder)
        # Provide download link
        return render_template('chat_with.html', contact=contact, messages=messages, download_link=image_path)
    
    return render_template('chat_with.html', contact=contact, messages=messages)

@app.route('/restore_chat_history', methods=['POST'])
def restore_chat_history():
    password = request.form['password']
    image_path = request.form['image_path']
    decrypted_history = decrypt_messages(image_path, password)
    # Add decrypted history back into chat
    restored_messages = [
        {
            'sender_id': int(msg.split(',')[0]),
            'timestamp': msg.split(',')[1],
            'message_text': msg.split(',')[2]
        } for msg in decrypted_history.split(',')
    ]
    return render_template('chat_with.html', restored_messages=restored_messages)

@app.route('/passwords')
def view_passwords():
    # Display passwords stored for the user
    conn = get_db_connection()
    passwords = conn.execute('SELECT * FROM passwords WHERE conversation_id IN (SELECT id FROM conversations WHERE user_id = ?)', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('passwords.html', passwords=passwords)

# Helper functions
def encrypt_conversation(conversation, password):
    fernet = Fernet(base64.urlsafe_b64encode(password.encode('utf-8').ljust(32)))
    return fernet.encrypt(conversation.encode('utf-8')).hex()

def decrypt_conversation(encrypted_data, password):
    fernet = Fernet(base64.urlsafe_b64encode(password.encode('utf-8').ljust(32)))
    return fernet.decrypt(bytes.fromhex(encrypted_data)).decode('utf-8')

def embed_in_image(data, folder):
    # Create a simple blank image and embed data as hex
    img = Image.new('RGB', (100, 100), color=(73, 109, 137))
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    hex_data = bytes(data, 'utf-8').hex()
    img_path = os.path.join(folder, f'conversation_{random.randint(1000, 9999)}.png')
    with open(img_path, 'ab') as f:
        f.write(bytes.fromhex(hex_data))
    return img_path

def decrypt_messages(image_path, password):
    # Read image and extract hex values backwards
    with open(image_path, 'rb') as img_file:
        img_file.seek(0, os.SEEK_END)
        hex_data = []
        while img_file.tell() > 0:
            img_file.seek(-1, os.SEEK_CUR)
            byte = img_file.read(1)
            hex_data.append(byte.hex())
            img_file.seek(-1, os.SEEK_CUR)
            if byte.hex() == 'ffd9':
                break
    # Convert hex data to string and decrypt
    encrypted_data = ''.join(reversed(hex_data))
    conversation_history = decrypt_conversation(encrypted_data, password)
    return conversation_history

if __name__ == '__main__':
    app.run(debug=True)