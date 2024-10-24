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
    # Logout logic
    session.clear()
    return redirect(url_for('login'))

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    # Chat logic
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    conversations = conn.execute('SELECT * FROM conversations WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('app_view.html', conversations=conversations)

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

@app.route('/chat_with/<contact>', methods=['GET', 'POST'])
def chat_with(contact):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    # Fetch conversation
    conversation = conn.execute('''
        SELECT * FROM conversations
        WHERE user_id = ? AND contact = ?
    ''', (session['user_id'], contact)).fetchone()
    # Fetch messages
    messages = conn.execute('''
        SELECT * FROM messages
        WHERE conversation_id = ?
        ORDER BY timestamp ASC
    ''', (conversation['id'],)).fetchall()
    # Handle message sending
    if request.method == 'POST':
        message_text = request.form['message']
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute('''
            INSERT INTO messages (conversation_id, sender_id, message_text, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (conversation['id'], session['user_id'], message_text, timestamp))
        conn.commit()
        # Update last_message_time in conversations table
        conn.execute('''
            UPDATE conversations
            SET last_message_time = ?
            WHERE id = ?
        ''', (timestamp, conversation['id']))
        conn.commit()
        # Redirect to avoid form resubmission
        return redirect(url_for('chat_with', contact=contact))
    # Select a random background image
    image_list = [f for f in os.listdir(IMAGES_FOLDER) if os.path.isfile(os.path.join(IMAGES_FOLDER, f))]
    background_image = random.choice(image_list) if image_list else None
    conn.close()
    return render_template('chat_with.html', contact=contact, messages=messages, background_image=background_image)

@app.route('/exit_chat/<contact>', methods=['GET', 'POST'])
def exit_chat(contact):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        password = request.form['password']
        messages = "Sample conversation text"  # Replace with actual messages
        # Encrypt messages
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        encrypted_text = cipher_suite.encrypt(messages.encode())
        # Embed in image
        image_name = embed_in_image(encrypted_text)
        # Update conversation in DB
        conn = get_db_connection()
        conn.execute('''
            UPDATE conversations
            SET encrypted_messages = ?, encryption_key = ?, image_name = ?
            WHERE user_id = ? AND contact = ?
        ''', (encrypted_text.decode(), key.decode(), image_name, session['user_id'], contact))
        conn.commit()
        conn.close()
        flash('Messages encrypted and stored.')
        return redirect(url_for('chat'))
    return render_template('encrypt.html', contact=contact)

@app.route('/open_conversation/<contact>', methods=['GET', 'POST'])
def open_conversation(contact):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    conversation = conn.execute('''
        SELECT * FROM conversations
        WHERE user_id = ? AND contact = ?
    ''', (session['user_id'], contact)).fetchone()
    conn.close()
    if request.method == 'POST':
        choice = request.form['choice']
        if choice == 'yes':
            password = request.form['password']
            # Decrypt messages
            decrypted_messages = decrypt_messages(conversation['encrypted_messages'], conversation['encryption_key'])
            flash('Messages restored.')
            # Display messages as needed
        else:
            flash('Starting a new conversation.')
            # Start a new conversation logic
        return redirect(url_for('chat_with', contact=contact))
    return render_template('restore_chat.html', contact=contact, conversation=conversation)

# Helper functions
def embed_in_image(encrypted_text):
    image_list = [f for f in os.listdir(IMAGES_FOLDER) if os.path.isfile(os.path.join(IMAGES_FOLDER, f))]
    random_image = random.choice(image_list)
    input_image_path = os.path.join(IMAGES_FOLDER, random_image)
    output_image_name = datetime.datetime.now().strftime("%d-%m-%Y") + '.png'
    output_image_path = os.path.join(IMAGES_FOLDER, output_image_name)

    # Open the image and embed the encrypted text
    with Image.open(input_image_path) as img:
        img.save(output_image_path, 'PNG')
    # For demonstration purposes, we're not actually embedding data into the image.
    # Implement steganography embedding as needed.
    return output_image_name

def decrypt_messages(encrypted_text, key):
    cipher_suite = Fernet(key.encode())
    decrypted_text = cipher_suite.decrypt(encrypted_text.encode()).decode()
    return decrypted_text

@app.route('/images/<path:filename>')
def images(filename):
    return send_from_directory(IMAGES_FOLDER, filename)

@app.route('about')
def 

if __name__ == '__main__':
    app.run(debug=True, port = 5000)
