from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, send_file, make_response
import sqlite3
import os
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin, current_user
from stegano import lsb
from werkzeug.utils import secure_filename
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
from PIL import Image

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
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
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
    contact_username = None
    if conversation_id:
        messages = conn.execute('''
            SELECT m.*, u.username AS sender_username
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.conversation_id = ?
            ORDER BY m.timestamp ASC
        ''', (conversation_id,)).fetchall()
        
        # Fetch the contact username
        contact = conn.execute('''
            SELECT u.username AS contact_username
            FROM conversations c
            JOIN users u ON (u.id = CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END)
            WHERE c.id = ?
        ''', (current_user.id, conversation_id)).fetchone()
        if contact:
            contact_username = contact['contact_username']
    
    conn.close()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('conversation.html', messages=messages, conversation_id=conversation_id, contact_username=contact_username)
    return render_template('chat.html', conversations=conversations, messages=messages, selected_conversation=conversation_id, contact_username=contact_username)

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

    # Fetch updated messages
    messages = conn.execute('''
        SELECT m.*, u.username AS sender_username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.conversation_id = ?
        ORDER BY m.timestamp ASC
    ''', (conversation_id,)).fetchall()
    conn.close()

    # Render the messages partial template
    rendered = render_template('messages.html', messages=messages)
    response = make_response(rendered)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response

@app.route('/exit_chat/<int:conversation_id>', methods=['GET', 'POST'])
@login_required
def exit_chat(conversation_id):
    if request.method == 'POST':
        option = request.form.get('option')
        conn = get_db_connection()
        conversation = conn.execute(
            'SELECT * FROM conversations WHERE id = ?', (conversation_id,)
        ).fetchone()
        
        if conversation:
            # Fetch messages
            messages = conn.execute(
                'SELECT message_text FROM messages WHERE conversation_id = ?', (conversation_id,)
            ).fetchall()
            message_texts = [message['message_text'] for message in messages]
            chat_content = "\n".join(message_texts)
            
            # Determine whether to encrypt
            if option == 'encrypt':
                # Generate a key and encrypt the content
                key = get_random_bytes(32)  # 32 bytes for AES-256
                encrypted_content = encrypt(chat_content, key)
                # Encode the encrypted content to base64 to store as text
                hidden_content = base64.b64encode(encrypted_content).decode('utf-8')
                
                # Save the key to a file
                key_filename = f'key_{conversation_id}.key'
                key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
                with open(key_path, 'wb') as key_file:
                    key_file.write(key)
                flash("Chat encrypted and saved. Please download your decryption key.")
            else:
                hidden_content = chat_content
                flash("Chat saved without encryption.")
            
            # Hide the content in an image using steganography
            images_dir = '/workspaces/PicChat/images'
            image_files = [
                f for f in os.listdir(images_dir) if os.path.isfile(os.path.join(images_dir, f))
            ]
            if not image_files:
                flash("No images available for steganography.")
                return redirect(url_for('chat'))
            selected_image = random.choice(image_files)
            selected_image_path = os.path.join(images_dir, selected_image)
            
            # Open the image and convert to RGB if necessary
            image = Image.open(selected_image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            image_name = f"chat_{conversation_id}.png"
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
            lsb.hide(image, hidden_content).save(image_path)
            
            # Update the conversation record
            conn.execute(
                'UPDATE conversations SET image_name = ? WHERE id = ?',
                (image_name, conversation_id)
            )
            # Delete messages from the database
            conn.execute(
                'DELETE FROM messages WHERE conversation_id = ?', (conversation_id,)
            )
            conn.commit()
            conn.close()
            
            if option == 'encrypt':
                # Provide the key file to the user
                return send_file(key_path, as_attachment=True)
            else:
                return send_file(image_path, as_attachment=True)
        else:
            flash("Conversation not found.")
            return redirect(url_for('chat'))
    else:
        # Render a template to choose encryption option
        return render_template('exit_chat.html', conversation_id=conversation_id)

def encrypt(content, key):
    # Ensure the key is 16, 24, or 32 bytes long
    key = key.ljust(32)[:32].encode('utf-8')
    # Generate a random Initialization Vector (IV)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad the content to be a multiple of block size and encrypt
    ct_bytes = cipher.encrypt(pad(content.encode('utf-8'), AES.block_size))
    # Prepend the IV for use in decryption
    return iv + ct_bytes

def decrypt(enc_content, key):
    iv = enc_content[:16]
    ct = enc_content[16:]
    cipher = AES.new(key.ljust(32)[:32], AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def extract_users_from_messages(messages):
    users = set()
    for message in messages:
        if ':' in message:
            username, _ = message.split(':', 1)
            users.add(username.strip())
    return users

def parse_message(message_text):
    if ':' in message_text:
        username, text = message_text.split(':', 1)
        return username.strip(), text.strip()
    else:
        return current_user.username, message_text.strip()

def find_conversation_with_users(users):
    conn = get_db_connection()
    # Fetch conversations involving the current user
    conversations = conn.execute('''
        SELECT c.id, u.username AS contact_username
        FROM conversations c
        JOIN users u ON (u.id = CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END)
        WHERE c.user1_id = ? OR c.user2_id = ?
    ''', (current_user.id, current_user.id, current_user.id)).fetchall()
    conn.close()
    for convo in conversations:
        if convo['contact_username'] in users:
            return convo['id']
    return None

def create_new_conversation(users):
    conn = get_db_connection()
    # For simplicity, pick one user to start the conversation with
    other_username = next(iter(users - {current_user.username}), None)
    if not other_username:
        other_username = current_user.username
    other_user = conn.execute('SELECT id FROM users WHERE username = ?', (other_username,)).fetchone()
    if other_user:
        user1_id, user2_id = sorted([current_user.id, other_user['id']])
        conn.execute('''
            INSERT INTO conversations (user1_id, user2_id, last_message_time)
            VALUES (?, ?, ?)
        ''', (
            user1_id,
            user2_id,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        conversation_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        return conversation_id
    else:
        conn.close()
        return None

@app.route('/start_conversation', methods=['POST'])
@login_required
def start_conversation():
    data = request.get_json()
    contact_id = data.get('contact_id')
    conn = get_db_connection()
    contact = conn.execute('SELECT * FROM users WHERE id = ?', (contact_id,)).fetchone()
    if not contact:
        flash('User does not exist.')
        conn.close()
        return jsonify({'error': 'User does not exist'}), 404
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
        return jsonify({'conversation_id': conversation['id']}), 200
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
    return jsonify({'conversation_id': conversation_id}), 200

@app.route('/download_conversation/<int:conversation_id>', methods=['GET'])
@login_required
def download_conversation(conversation_id):
    conn = get_db_connection()
    conversation = conn.execute('SELECT * FROM conversations WHERE id = ?', (conversation_id,)).fetchone()
    if conversation:
        messages = conn.execute('SELECT message_text FROM messages WHERE conversation_id = ?', (conversation_id,)).fetchall()
        message_texts = [message['message_text'] for message in messages]
        chat_content = "\n".join(message_texts)
        
        # Randomly select an image from the /workspaces/PicChat/images directory
        images_dir = '/workspaces/PicChat/images'
        image_files = [f for f in os.listdir(images_dir) if os.path.isfile(os.path.join(images_dir, f))]
        if not image_files:
            flash("No images available for steganography.")
            return redirect(url_for('chat'))
        
        selected_image = random.choice(image_files)
        selected_image_path = os.path.join(images_dir, selected_image)
        
        # Open the image and convert to RGB if necessary
        image = Image.open(selected_image_path)
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Save the steganographed image
        image_name = f"chat_{conversation_id}.png"
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
        lsb.hide(image, chat_content).save(image_path)
        
        return send_file(image_path, as_attachment=True)
    else:
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
    query = data.get('query', '')
    conn = get_db_connection()
    users = conn.execute("SELECT id, username FROM users WHERE username LIKE ?", ('%' + query + '%',)).fetchall()
    conn.close()
    results = [{'id': user['id'], 'username': user['username']} for user in users]
    return jsonify(results=results)

@app.route('/restore_chat', methods=['GET', 'POST'])
@login_required
def restore_chat():
    if request.method == 'POST':
        decrypt_option = request.form.get('decrypt_option')
        key = request.form.get('key')
        image_file = request.files.get('image_file')

        if not image_file:
            flash("No image file provided.")
            return redirect(url_for('chat'))

        # Save the uploaded image temporarily
        image_filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
        image_file.save(image_path)

        try:
            # Extract hidden content using steganography
            hidden_content = lsb.reveal(image_path)
            if not hidden_content:
                flash("No hidden content found in the image.")
                os.remove(image_path)
                return redirect(url_for('chat'))

            # Decrypt if necessary
            if decrypt_option == 'encrypted':
                if not key:
                    flash("Decryption key is required.")
                    os.remove(image_path)
                    return redirect(url_for('chat'))
                # Decode from base64 and decrypt
                encrypted_content = base64.b64decode(hidden_content)
                restored_chat_content = decrypt(encrypted_content, key.encode('utf-8'))
            else:
                restored_chat_content = hidden_content

            # Process the restored chat content
            messages = restored_chat_content.split("\n")
            # Check if the restored conversation includes the current user
            conversation_users = extract_users_from_messages(messages)
            if current_user.username in conversation_users:
                # Check if a conversation with these users exists
                conversation_id = find_conversation_with_users(conversation_users)
                if not conversation_id:
                    # Create a new conversation
                    conversation_id = create_new_conversation(conversation_users)
            else:
                # Create a new conversation
                conversation_id = create_new_conversation(conversation_users)

            # Insert messages into the database
            conn = get_db_connection()
            for message_text in messages:
                # Assuming messages are in "username: message" format
                sender_username, text = parse_message(message_text)
                sender = conn.execute('SELECT id FROM users WHERE username = ?', (sender_username,)).fetchone()
                if sender:
                    sender_id = sender['id']
                else:
                    sender_id = current_user.id  # Default to current user
                conn.execute('''
                    INSERT INTO messages (conversation_id, sender_id, message_text, timestamp)
                    VALUES (?, ?, ?, ?)
                ''', (
                    conversation_id,
                    sender_id,
                    text,
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ))
            conn.commit()
            conn.close()
            flash("Conversation restored successfully.")
        except Exception as e:
            flash("Failed to restore conversation.")
        finally:
            os.remove(image_path)  # Clean up the uploaded image
        return redirect(url_for('chat', conversation_id=conversation_id))
    else:
        return redirect(url_for('chat'))

@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True, port=5001)