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
from flask_login import LoginManager, login_required

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
    # Initialize your database schema here
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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        flash('Signup successful! Please log in.')
        return redirect(url_for('login'))
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

app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    contact = request.args.get('contact', 'EmptyNoUserSelected')
    
    conn = get_db_connection()
    conversations = conn.execute('SELECT * FROM conversations WHERE user_id = ?', (session['user_id'],)).fetchall()
    image_list = [f for f in os.listdir(IMAGES_FOLDER) if os.path.isfile(os.path.join(IMAGES_FOLDER, f))]
    background_image = random.choice(image_list) if image_list else None
    conn.close()
    
    if contact == 'EmptyNoUserSelected':
        return render_template('chat_with.html', conversations=conversations, contact=None, messages=None, background_image=background_image, no_user_selected=True)
    
    return render_template('chat_with.html', conversations=conversations, contact=contact, messages=None, background_image=background_image, no_user_selected=False)
@app.route('/start_conversation', methods=['POST'])
@login_required
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
@login_required
def chat_with(contact):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if not contact:
        return {'error': 'No contact selected'}, 400
    
    conn = get_db_connection()
    conversation = conn.execute('''
        SELECT * FROM conversations
        WHERE user_id = ? AND contact = ?
    ''', (session['user_id'], contact)).fetchone()
    
    if not conversation:
        conn.close()
        return redirect(url_for('chat'))
    
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
    
    messages = conn.execute('''
        SELECT * FROM messages
        WHERE conversation_id = ?
        ORDER BY timestamp ASC
    ''', (conversation['id'],)).fetchall()
    
    # Select a random background image
    image_list = [f for f in os.listdir(IMAGES_FOLDER) if os.path.isfile(os.path.join(IMAGES_FOLDER, f))]
    background_image = random.choice(image_list) if image_list else None
    
    conn.close()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        messages_html = render_template('messages.html', messages=messages, contact=contact)
        return {'messages_html': messages_html}
    
    return render_template('chat_with.html', contact=contact, messages=messages, background_image=background_image)

@app.route('/exit_chat/<contact>', methods=['GET', 'POST'])
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

@app.route('/restore_chat', methods=['POST'])
def restore_chat():
    image_path = request.form['image_path']
    password = request.form['password']
    decrypted_text = decrypt_messages(image_path, password)
    # Convert the decrypted text back to messages and display them
    messages = []
    for line in decrypted_text.split('\n'):
        sender_id, timestamp, message_text = line.split(',')
        messages.append({'sender_id': sender_id, 'timestamp': timestamp, 'message_text': message_text})
    return render_template('chat_with.html', messages=messages, contact=request.form['contact'])

@app.route('/images/<path:filename>')
def images(filename):
    return send_from_directory(IMAGES_FOLDER, filename)

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
