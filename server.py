try:
    from flask import Flask, request, jsonify, send_file
    from flask_socketio import SocketIO, emit, join_room, leave_room
except Exception as e:
    raise RuntimeError("Flask and flask-socketio are required. Install them with 'pip install -r requirements.txt'") from e
import os
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
import sqlite3
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB limit

# Initialize SocketIO with eventlet
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Track connected users: {api_key: sid}
connected_users = {}


def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('filetransfer.db')
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            friend_code TEXT UNIQUE NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS friends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            friend_user_id INTEGER,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (friend_user_id) REFERENCES users(id),
            UNIQUE(user_id, friend_user_id)
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            sender_id INTEGER,
            receiver_id INTEGER,
            file_path TEXT NOT NULL,
            file_size INTEGER,
            downloaded BOOLEAN DEFAULT FALSE,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            data TEXT,
            read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()


init_db()


# Helper functions
def generate_friend_code():
    """Generate a unique friend code like: XXXX-XXXX-XXXX"""
    parts = [secrets.token_hex(2).upper() for _ in range(3)]
    return '-'.join(parts)


def generate_api_key():
    """Generate a secure API key"""
    return secrets.token_urlsafe(32)


def hash_password(password):
    """Hash password with salt"""
    salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{hash_obj.hex()}"


def verify_password(password, password_hash):
    """Verify password against hash"""
    salt, hash_value = password_hash.split(':')
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return hash_obj.hex() == hash_value


def get_db():
    """Get database connection"""
    return sqlite3.connect('filetransfer.db')


def get_user_by_api_key(api_key):
    """Get user by API key"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, username, friend_code FROM users WHERE api_key = ?', (api_key,))
    user = c.fetchone()
    conn.close()
    if user:
        return {'id': user[0], 'username': user[1], 'friend_code': user[2]}
    return None


def get_user_api_key_by_id(user_id):
    """Get user's API key by user ID"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT api_key FROM users WHERE id = ?', (user_id,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None


def send_notification(user_id, notif_type, message, data=None):
    """Send real-time notification to a user"""
    conn = get_db()
    c = conn.cursor()
    
    # Store notification in database
    c.execute('''
        INSERT INTO notifications (user_id, type, message, data)
        VALUES (?, ?, ?, ?)
    ''', (user_id, notif_type, message, json.dumps(data) if data else None))
    conn.commit()
    notif_id = c.lastrowid
    conn.close()
    
    # Get user's API key to find their socket room
    api_key = get_user_api_key_by_id(user_id)
    if api_key and api_key in connected_users:
        socketio.emit('notification', {
            'id': notif_id,
            'type': notif_type,
            'message': message,
            'data': data,
            'timestamp': datetime.now().isoformat()
        }, room=connected_users[api_key])


def require_auth(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        user = get_user_by_api_key(api_key)
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        request.user = user
        return f(*args, **kwargs)
    return decorated


# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")


@socketio.on('authenticate')
def handle_authenticate(data):
    """Handle client authentication via WebSocket"""
    api_key = data.get('api_key')
    user = get_user_by_api_key(api_key)
    
    if user:
        connected_users[api_key] = request.sid
        join_room(request.sid)
        emit('authenticated', {
            'status': 'success',
            'username': user['username'],
            'friend_code': user['friend_code']
        })
        print(f"User {user['username']} authenticated")
        
        # Send pending notifications
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT id, type, message, data, created_at 
            FROM notifications 
            WHERE user_id = ? AND read = FALSE
            ORDER BY created_at DESC
            LIMIT 50
        ''', (user['id'],))
        notifications = c.fetchall()
        conn.close()
        
        for notif in notifications:
            emit('notification', {
                'id': notif[0],
                'type': notif[1],
                'message': notif[2],
                'data': json.loads(notif[3]) if notif[3] else None,
                'timestamp': notif[4]
            })
    else:
        emit('authenticated', {'status': 'error', 'message': 'Invalid API key'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    for api_key, sid in list(connected_users.items()):
        if sid == request.sid:
            del connected_users[api_key]
            break
    print(f"Client disconnected: {request.sid}")


@socketio.on('mark_read')
def handle_mark_read(data):
    """Mark notification as read"""
    notif_id = data.get('notification_id')
    if notif_id:
        conn = get_db()
        c = conn.cursor()
        c.execute('UPDATE notifications SET read = TRUE WHERE id = ?', (notif_id,))
        conn.commit()
        conn.close()


# REST Routes
@app.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    friend_code = generate_friend_code()
    api_key = generate_api_key()
    password_hash = hash_password(password)
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        c.execute('''
            INSERT INTO users (username, password_hash, friend_code, api_key)
            VALUES (?, ?, ?, ?)
        ''', (username, password_hash, friend_code, api_key))
        conn.commit()
        
        return jsonify({
            'message': 'Registration successful',
            'friend_code': friend_code,
            'api_key': api_key
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    finally:
        conn.close()


@app.route('/login', methods=['POST'])
def login():
    """Login and get API key"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT password_hash, api_key, friend_code FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    
    if not user or not verify_password(password, user[0]):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    return jsonify({
        'api_key': user[1],
        'friend_code': user[2]
    })


@app.route('/friends/add', methods=['POST'])
@require_auth
def add_friend():
    """Add a friend by friend code"""
    data = request.json
    friend_code = data.get('friend_code')
    
    if not friend_code:
        return jsonify({'error': 'Friend code required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT id, username FROM users WHERE friend_code = ?', (friend_code,))
    friend = c.fetchone()
    
    if not friend:
        conn.close()
        return jsonify({'error': 'Friend code not found'}), 404
    
    if friend[0] == request.user['id']:
        conn.close()
        return jsonify({'error': 'Cannot add yourself as a friend'}), 400
    
    try:
        c.execute('INSERT INTO friends (user_id, friend_user_id) VALUES (?, ?)',
                  (request.user['id'], friend[0]))
        c.execute('INSERT INTO friends (user_id, friend_user_id) VALUES (?, ?)',
                  (friend[0], request.user['id']))
        conn.commit()
        
        # Send notification to the friend
        send_notification(
            friend[0],
            'friend_added',
            f"{request.user['username']} added you as a friend!",
            {'username': request.user['username'], 'friend_code': request.user['friend_code']}
        )
        
        return jsonify({
            'message': f'Added {friend[1]} as a friend',
            'friend_username': friend[1]
        })
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Already friends'}), 409
    finally:
        conn.close()


@app.route('/friends', methods=['GET'])
@require_auth
def list_friends():
    """List all friends with online status"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT u.id, u.username, u.friend_code 
        FROM friends f
        JOIN users u ON f.friend_user_id = u.id
        WHERE f.user_id = ?
    ''', (request.user['id'],))
    friends = c.fetchall()
    conn.close()
    
    # Check online status
    friend_list = []
    for f in friends:
        api_key = get_user_api_key_by_id(f[0])
        online = api_key in connected_users if api_key else False
        friend_list.append({
            'username': f[1],
            'friend_code': f[2],
            'online': online
        })
    
    return jsonify({'friends': friend_list})


@app.route('/upload', methods=['POST'])
@require_auth
def upload_file():
    """Upload a file to send to a friend"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    recipient_code = request.form.get('recipient_code')
    
    if not recipient_code:
        return jsonify({'error': 'Recipient friend code required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT id, username FROM users WHERE friend_code = ?', (recipient_code,))
    recipient = c.fetchone()
    
    if not recipient:
        conn.close()
        return jsonify({'error': 'Recipient not found'}), 404
    
    c.execute('''
        SELECT 1 FROM friends 
        WHERE user_id = ? AND friend_user_id = ?
    ''', (request.user['id'], recipient[0]))
    
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Recipient is not in your friend list'}), 403
    
    file_id = str(uuid.uuid4())
    filename = file.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
    file.save(file_path)
    file_size = os.path.getsize(file_path)
    expires_at = datetime.now() + timedelta(days=7)
    
    c.execute('''
        INSERT INTO files (file_id, filename, sender_id, receiver_id, file_path, file_size, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (file_id, filename, request.user['id'], recipient[0], file_path, file_size, expires_at))
    conn.commit()
    conn.close()
    
    # Send real-time notification to recipient
    send_notification(
        recipient[0],
        'file_received',
        f"{request.user['username']} sent you a file: {filename}",
        {
            'file_id': file_id,
            'filename': filename,
            'file_size': file_size,
            'sender': request.user['username'],
            'sender_code': request.user['friend_code']
        }
    )
    
    return jsonify({
        'message': 'File uploaded successfully',
        'file_id': file_id,
        'recipient': recipient[1],
        'expires_at': expires_at.isoformat()
    })


@app.route('/files/inbox', methods=['GET'])
@require_auth
def inbox():
    """List files sent to you"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT f.file_id, f.filename, f.file_size, u.username, u.friend_code, f.created_at, f.downloaded
        FROM files f
        JOIN users u ON f.sender_id = u.id
        WHERE f.receiver_id = ? AND f.expires_at > ?
        ORDER BY f.created_at DESC
    ''', (request.user['id'], datetime.now()))
    files = c.fetchall()
    conn.close()
    
    return jsonify({
        'files': [{
            'file_id': f[0],
            'filename': f[1],
            'file_size': f[2],
            'from_username': f[3],
            'from_code': f[4],
            'sent_at': f[5],
            'downloaded': bool(f[6])
        } for f in files]
    })


@app.route('/files/sent', methods=['GET'])
@require_auth
def sent_files():
    """List files you've sent"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT f.file_id, f.filename, f.file_size, u.username, u.friend_code, f.created_at, f.downloaded
        FROM files f
        JOIN users u ON f.receiver_id = u.id
        WHERE f.sender_id = ?
        ORDER BY f.created_at DESC
    ''', (request.user['id'],))
    files = c.fetchall()
    conn.close()
    
    return jsonify({
        'files': [{
            'file_id': f[0],
            'filename': f[1],
            'file_size': f[2],
            'to_username': f[3],
            'to_code': f[4],
            'sent_at': f[5],
            'downloaded': bool(f[6])
        } for f in files]
    })


@app.route('/download/<file_id>', methods=['GET'])
@require_auth
def download_file(file_id):
    """Download a file sent to you"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT file_path, filename, sender_id FROM files 
        WHERE file_id = ? AND receiver_id = ? AND expires_at > ?
    ''', (file_id, request.user['id'], datetime.now()))
    file_info = c.fetchone()
    
    if not file_info:
        conn.close()
        return jsonify({'error': 'File not found or expired'}), 404
    
    c.execute('UPDATE files SET downloaded = TRUE WHERE file_id = ?', (file_id,))
    conn.commit()
    conn.close()
    
    # Notify sender that file was downloaded
    send_notification(
        file_info[2],
        'file_downloaded',
        f"{request.user['username']} downloaded {file_info[1]}",
        {
            'file_id': file_id,
            'filename': file_info[1],
            'downloaded_by': request.user['username']
        }
    )
    
    return send_file(file_info[0], download_name=file_info[1], as_attachment=True)


@app.route('/notifications', methods=['GET'])
@require_auth
def get_notifications():
    """Get user's notifications"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT id, type, message, data, read, created_at
        FROM notifications
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 100
    ''', (request.user['id'],))
    notifications = c.fetchall()
    conn.close()
    
    return jsonify({
        'notifications': [{
            'id': n[0],
            'type': n[1],
            'message': n[2],
            'data': json.loads(n[3]) if n[3] else None,
            'read': bool(n[4]),
            'timestamp': n[5]
        } for n in notifications]
    })


if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)