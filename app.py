from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, send_file
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
app.config['WTF_CSRF_TIME_LIMIT'] = None  # Disable CSRF token expiration
app.config['WTF_CSRF_SSL_STRICT'] = False  # Allow HTTP (not just HTTPS)
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
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1_id INTEGER NOT NULL,
        user2_id INTEGER NOT NULL,
        last_message_time TEXT,
        image_name TEXT,
        FOREIGN KEY (user1_id) REFERENCES users (id),
        FOREIGN KEY (user2_id) REFERENCES users (id)
    );
    CREATE TABLE IF NOT EXISTS messages (
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
    if not os.path.exists(DATABASE):
        if not os.path.exists(SCHEMA_FILE):
            create_schema_file()
        with app.app_context():
            db = get_db_connection()
            with app.open_resource(SCHEMA_FILE, mode='r') as f:
                db.cursor().executescript(f.read())
            db.commit()
            db.close()

init_db()

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
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
    conversation_id = request.args.get('conversation_id')
    conn = get_db_connection()
    
    # Fetch conversation list
    conversations = conn.execute('''
        SELECT c.*, u.username AS contact_username
        FROM conversations c
        JOIN users u ON (u.id = CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END)
        WHERE c.user1_id = ? OR c.user2_id = ?
        ORDER BY c.last_message_time DESC
    ''', (current_user.id, current_user.id, current_user.id)).fetchall()
    # Fetch messages if a conversation_id is provided
    messages = None
    if conversation_id:
        messages = conn.execute('''
            SELECT m.*, u.username AS sender_username
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.conversation_id = ?
            ORDER BY m.timestamp ASC
        ''', (conversation_id,)).fetchall()
    conn.close()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('conversation.html', messages=messages, conversation_id=conversation_id)
    return render_template('chat.html', conversations=conversations, messages=messages, selected_conversation=conversation_id)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    conversation_id = request.form['conversation_id']
    message_text = request.form['message_text']
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO messages (conversation_id, sender_id, message_text, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (conversation_id, current_user.id, message_text, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.execute('''
        UPDATE conversations
        SET last_message_time = ?
        WHERE id = ?
    ''', (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), conversation_id))
    conn.commit()
    conn.close()
    return redirect(url_for('chat', conversation_id=conversation_id))

@app.route('/exit_chat/<int:conversation_id>', methods=['POST'])
@login_required
def exit_chat(conversation_id):
    conn = get_db_connection()
    conversation = conn.execute('SELECT * FROM conversations WHERE id = ?', (conversation_id,)).fetchone()
    if conversation:
        messages = conn.execute('SELECT message_text FROM messages WHERE conversation_id = ?', (conversation_id,)).fetchall()
        message_texts = [message['message_text'] for message in messages]
        chat_content = "\n".join(message_texts)
        image_name = f"chat_{conversation_id}.png"
        lsb.hide(os.path.join(app.config['UPLOAD_FOLDER'], image_name), chat_content).save(image_name)
        conn.execute('UPDATE conversations SET image_name = ? WHERE id = ?', (image_name, conversation_id))
        conn.execute('DELETE FROM messages WHERE conversation_id = ?', (conversation_id,))
        conn.commit()
    conn.close()
    flash("Chat saved and exited.")
    return redirect(url_for('chat'))

@app.route('/start_conversation', methods=['POST'])
@login_required
def start_conversation():
    data = request.get_json()
    contact_username = data.get('contact', '')
    conn = get_db_connection()
    contact = conn.execute('SELECT * FROM users WHERE username = ?', (contact_username,)).fetchone()
    if not contact:
        flash('User does not exist.')
        conn.close()
        return redirect(url_for('chat'))
    contact_id = contact['id']
    current_user_id = current_user.id
    # Ensure consistent ordering
    user1_id, user2_id = sorted([current_user_id, contact_id])
    # Check if conversation already exists
    conversation = conn.execute('''
        SELECT * FROM conversations WHERE user1_id = ? AND user2_id = ?
    ''', (user1_id, user2_id)).fetchone()
    if conversation:
        conn.close()
        return redirect(url_for('chat', conversation_id=conversation['id']))
    # Create new conversation
    conn.execute('''
        INSERT INTO conversations (user1_id, user2_id, last_message_time)
        VALUES (?, ?, ?)
    ''', (user1_id, user2_id, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    # Retrieve the new conversation ID
    conversation_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    conn.close()
    flash('Conversation started.')
    return redirect(url_for('chat', conversation_id=conversation_id))

@app.route('/download_conversation/<int:conversation_id>', methods=['GET'])
@login_required
def download_conversation(conversation_id):
    conn = get_db_connection()
    conversation = conn.execute('SELECT * FROM conversations WHERE id = ?', (conversation_id,)).fetchone()
    if conversation:
        messages = conn.execute('SELECT message_text FROM messages WHERE conversation_id = ?', (conversation_id,)).fetchall()
        message_texts = [message['message_text'] for message in messages]
        chat_content = "\n".join(message_texts)
        image_name = f"chat_{conversation_id}.png"
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
        lsb.hide(image_path, chat_content).save(image_path)
        conn.execute('UPDATE conversations SET image_name = ? WHERE id = ?', (image_name, conversation_id))
        conn.commit()
        conn.close()
        return send_file(image_path, as_attachment=True)
    conn.close()
    flash("Conversation not found.")
    return redirect(url_for('chat'))

@app.route('/delete_conversation/<int:conversation_id>', methods=['POST'])
@login_required
def delete_conversation(conversation_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM messages WHERE conversation_id = ?', (conversation_id,))
    conn.execute('DELETE FROM conversations WHERE id = ?', (conversation_id,))
    conn.commit()
    conn.close()
    flash("Conversation deleted.")
    return redirect(url_for('chat'))

@app.route('/chat_settings/<int:conversation_id>', methods=['GET', 'POST'])
@login_required
def chat_settings(conversation_id):
    if request.method == 'POST':
        background_image = request.files.get('background_image')
        if background_image and allowed_file(background_image.filename):
            filename = secure_filename(background_image.filename)
            background_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            conn = get_db_connection()
            conn.execute('UPDATE conversations SET background_image = ? WHERE id = ?', (filename, conversation_id))
            conn.commit()
            conn.close()
            flash("Chat settings updated.")
            return redirect(url_for('chat', conversation_id=conversation_id))
    return render_template('chat_settings.html', conversation_id=conversation_id)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/search_users', methods=['POST'])
@login_required
def search_users():
    data = request.get_json()
    search_query = data.get('search_query', '')
    conn = get_db_connection()
    users = conn.execute("SELECT username FROM users WHERE username LIKE ?", ('%' + search_query + '%',)).fetchall()
    conn.close()
    usernames = [user['username'] for user in users]
    return jsonify(usernames=usernames)

@app.route('/restore_chat/<int:conversation_id>', methods=['GET'])
@login_required
def restore_chat(conversation_id):
    conn = get_db_connection()
    conversation = conn.execute('SELECT * FROM conversations WHERE id = ?', (conversation_id,)).fetchone()
    conn.close()
    if not conversation or not conversation['image_name']:
        flash("No chat history to restore.")
        return redirect(url_for('chat', conversation_id=conversation_id))
    # Path to the saved image with the chat data
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], conversation['image_name'])
    try:
        # Decode the hidden chat content from the image
        restored_chat_content = lsb.reveal(image_path)
        if not restored_chat_content:
            flash("Failed to restore chat.")
            return redirect(url_for('chat', conversation_id=conversation_id))
        # Reinsert the restored messages into the database
        messages = restored_chat_content.split("\n")
        conn = get_db_connection()
        for message_text in messages:
            conn.execute('''
                INSERT INTO messages (conversation_id, sender_id, message_text, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (conversation_id, current_user.id, message_text, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
        flash("Chat restored.")
    except Exception as e:
        flash("Failed to restore chat.")
    return redirect(url_for('chat', conversation_id=conversation_id))

@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True)