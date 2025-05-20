from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3
import os
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
app.config['DATABASE'] = '/tmp/database.db'
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")
online_users = set()

# Database functions
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # Принудительно создаем все таблицы с IF NOT EXISTS
        cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            subject TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS lesson_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            teacher_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            topic TEXT NOT NULL,
            requested_time TIMESTAMP NOT NULL,
            status TEXT DEFAULT 'pending',
            response_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES users (id),
            FOREIGN KEY (teacher_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        );
        '''), [generate_password_hash('admin123', method='sha256')]
        cursor.execute("SELECT id FROM users WHERE id = 0")
        admin = cursor.fetchone()
        if not admin:
            hashed_password = generate_password_hash('admin123', method='sha256')
            cursor.execute(
                "INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)",
                (0, 'admin', 'admin@eduportal.com', hashed_password, 'admin')
            )
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        db = get_db()
        try:
            hashed_password = generate_password_hash(password, method='sha256')
            db.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed_password)
            )
            db.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('This username or email is already taken', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('You have successfully logged in', 'success')
            return redirect(url_for('dashboard'))

        flash('Incorrect username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    role = session['role']

    if role == 'student':
        requests = query_db('''
        SELECT lr.*, u.username as teacher_name 
        FROM lesson_requests lr
        JOIN users u ON lr.teacher_id = u.id
        WHERE lr.student_id = ?
        ORDER BY lr.created_at DESC
        ''', [user_id])
    else:
        requests = query_db('''
        SELECT lr.*, u.username as student_name 
        FROM lesson_requests lr
        JOIN users u ON lr.student_id = u.id
        WHERE lr.teacher_id = ?
        ORDER BY lr.created_at DESC
        ''', [user_id])

    return render_template('dashboard.html', requests=requests)

@app.route('/request-lesson', methods=['GET', 'POST'])
def request_lesson():
    if 'user_id' not in session or session['role'] != 'student':
        flash('Only students can send requests', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        subject = request.form['subject']
        teacher_id = request.form['teacher']
        topic = request.form['topic']
        requested_time = request.form['requested_time']

        teacher = query_db('SELECT id FROM users WHERE id = ? AND role = ? AND subject = ?',
                           [teacher_id, 'teacher', subject], one=True)

        if not teacher:
            flash('Teacher for this subject not found', 'danger')
            return redirect(url_for('request_lesson'))

        db = get_db()
        db.execute('''
        INSERT INTO lesson_requests (student_id, teacher_id, subject, topic, requested_time)
        VALUES (?, ?, ?, ?, ?)
        ''', [session['user_id'], teacher_id, subject, topic, requested_time])
        db.commit()

        flash('Request sent to the teacher', 'success')
        return redirect(url_for('dashboard'))

    # Get list of subjects with available teachers
    subjects = query_db("SELECT DISTINCT subject FROM users WHERE role = 'teacher' AND subject IS NOT NULL")

    return render_template('request_lesson.html', subjects=subjects)

@app.route('/get-teachers/<subject>')
def get_teachers(subject):
    if 'user_id' not in session or session['role'] != 'student':
        return {'error': 'Unauthorized'}, 401

    teachers = query_db("SELECT id, username FROM users WHERE role = 'teacher' AND subject = ?", [subject])
    teachers_list = [{'id': t['id'], 'username': t['username']} for t in teachers]
    return {'teachers': teachers_list}

@app.route('/teacher-requests')
def teacher_requests():
    if 'user_id' not in session or session['role'] != 'teacher':
        flash('Only teachers can view requests', 'danger')
        return redirect(url_for('dashboard'))

    requests = query_db('''
    SELECT lr.*, u.username as student_name 
    FROM lesson_requests lr
    JOIN users u ON lr.student_id = u.id
    WHERE lr.teacher_id = ? AND lr.status = 'pending'
    ORDER BY lr.created_at DESC
    ''', [session['user_id']])

    return render_template('teacher_requests.html', requests=requests)

@app.route('/respond-request/<int:request_id>', methods=['POST'])
def respond_request(request_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        flash('Only teachers can respond to requests', 'danger')
        return redirect(url_for('dashboard'))

    action = request.form['action']
    message = request.form.get('message', '')

    status = 'accepted' if action == 'accept' else 'rejected'

    db = get_db()
    db.execute('''
    UPDATE lesson_requests 
    SET status = ?, response_message = ?
    WHERE id = ? AND teacher_id = ?
    ''', [status, message, request_id, session['user_id']])
    db.commit()

    flash('Request updated', 'success')
    return redirect(url_for('teacher_requests'))

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session or session['user_id'] != 0:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))

    users = query_db("SELECT * FROM users WHERE id != 0")
    subjects = ['Math', 'Physics', 'Chemistry', 'Biology', 'History', 'Literature', 'Programming']
    return render_template('admin_panel.html', users=users, subjects=subjects)

@app.route('/update-role/<int:user_id>', methods=['POST'])
def update_role(user_id):
    if 'user_id' not in session or session['user_id'] != 0:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))

    new_role = request.form['role']
    subject = request.form.get('subject', None) if new_role == 'teacher' else None

    if new_role not in ['teacher', 'student']:
        flash('Invalid role', 'danger')
        return redirect(url_for('admin_panel'))

    db = get_db()
    db.execute("UPDATE users SET role = ?, subject = ? WHERE id = ?", [new_role, subject, user_id])
    db.commit()

    flash('User role updated', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/delete-user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session['user_id'] != 0:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))

    db = get_db()

    # Delete related requests
    db.execute("DELETE FROM lesson_requests WHERE student_id = ? OR teacher_id = ?",
               [user_id, user_id])

    # Delete user
    db.execute("DELETE FROM users WHERE id = ?", [user_id])
    db.commit()

    flash('User deleted', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html')


@app.route('/api/contacts')
def get_contacts():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Требуется авторизация'}), 401

    try:
        user_id = session['user_id']
        role = session['role']

        # Получаем контакты и последнее сообщение для каждого
        if role == 'student':
            contacts = query_db('''
                SELECT u.id, u.username, 
                       MAX(m.timestamp) as last_message_time,
                       (SELECT COUNT(*) FROM messages 
                        WHERE receiver_id = ? AND sender_id = u.id AND is_read = FALSE) as unread_count
                FROM users u
                JOIN lesson_requests lr ON u.id = lr.teacher_id
                LEFT JOIN messages m ON (m.sender_id = u.id AND m.receiver_id = ?) 
                                    OR (m.sender_id = ? AND m.receiver_id = u.id)
                WHERE lr.student_id = ? AND lr.status = 'accepted'
                GROUP BY u.id
                ORDER BY last_message_time DESC NULLS LAST
            ''', [user_id, user_id, user_id, user_id])
        else:
            contacts = query_db('''
                SELECT u.id, u.username, 
                       MAX(m.timestamp) as last_message_time,
                       (SELECT COUNT(*) FROM messages 
                        WHERE receiver_id = ? AND sender_id = u.id AND is_read = FALSE) as unread_count
                FROM users u
                JOIN lesson_requests lr ON u.id = lr.student_id
                LEFT JOIN messages m ON (m.sender_id = u.id AND m.receiver_id = ?) 
                                    OR (m.sender_id = ? AND m.receiver_id = u.id)
                WHERE lr.teacher_id = ? AND lr.status = 'accepted'
                GROUP BY u.id
                ORDER BY last_message_time DESC NULLS LAST
            ''', [user_id, user_id, user_id, user_id])

        return jsonify({
            'success': True,
            'contacts': [dict(c) for c in contacts],
            'updated_at': datetime.now().strftime('%H:%M:%S')
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Ошибка сервера: {str(e)}'
        }), 500


@app.route('/api/messages/<int:contact_id>')
def get_messages(contact_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Требуется авторизация'}), 401

    try:
        # Помечаем сообщения как прочитанные
        db = get_db()
        db.execute('''
            UPDATE messages 
            SET is_read = TRUE 
            WHERE sender_id = ? AND receiver_id = ? AND is_read = FALSE
        ''', [contact_id, session['user_id']])
        db.commit()

        # Получаем сообщения
        messages = query_db('''
            SELECT m.*, u.username as sender_name 
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = ? AND m.receiver_id = ?) 
               OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.timestamp
            LIMIT 100
        ''', [session['user_id'], contact_id, contact_id, session['user_id']])

        return jsonify([dict(msg) for msg in messages])

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/messages/read/<int:contact_id>', methods=['POST'])
def mark_as_read(contact_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Требуется авторизация'}), 401

    try:
        db = get_db()
        db.execute('''
            UPDATE messages 
            SET is_read = TRUE 
            WHERE sender_id = ? AND receiver_id = ? AND is_read = FALSE
        ''', [contact_id, session['user_id']])
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        user_id = session['user_id']
        join_room(str(user_id))
        online_users.add(user_id)
        emit('user_status', {
            'user_id': user_id,
            'status': 'online'
        }, broadcast=True)
        emit('connection_status', {
            'status': 'connected',
            'user_id': user_id,
            'username': session.get('username', 'Unknown'),
            'online_users': list(online_users)
        }, room=str(user_id))

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        user_id = session['user_id']
        if user_id in online_users:
            online_users.remove(user_id)
        emit('user_status', {
            'user_id': user_id,
            'status': 'offline'
        }, broadcast=True)

@socketio.on('send_message')
def handle_send_message(data):
    try:
        if 'user_id' not in session:
            return {'error': 'Требуется авторизация'}

        required = ['receiver_id', 'message']
        if not all(k in data for k in required):
            return {'error': 'Недостаточно данных'}

        # Сохраняем сообщение в БД
        db = get_db()
        cursor = db.execute(
            "INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)",
            (session['user_id'], data['receiver_id'], data['message'])
        )
        message_id = cursor.lastrowid
        db.commit()

        # Получаем данные отправителя
        sender = query_db(
            "SELECT username FROM users WHERE id = ?",
            [session['user_id']],
            one=True
        )

        # Формируем данные сообщения
        message_data = {
            'id': message_id,
            'sender_id': session['user_id'],
            'sender_name': sender['username'],
            'message': data['message'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'is_read': False
        }

        # Отправляем сообщение получателю
        emit('new_message', message_data, room=str(data['receiver_id']))

        # Отправляем копию себе для синхронизации
        emit('new_message', message_data, room=str(session['user_id']))

        # Обновляем список контактов у получателя и отправителя
        emit('update_contacts', room=str(data['receiver_id']))
        emit('update_contacts', room=str(session['user_id']))

        return {'success': True, 'message_id': message_id}

    except Exception as e:
        return {'error': str(e)}

if __name__ == '__main__':
    if not os.path.exists(app.config['DATABASE']):
        with app.app_context():
            init_db()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
