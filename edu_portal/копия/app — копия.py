from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
app.config['DATABASE'] = 'eduportal.db'


# Функции для работы с БД
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

        # Создаем таблицу пользователей
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Создаем таблицу запросов на занятия
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS lesson_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            teacher_id INTEGER NOT NULL,
            topic TEXT NOT NULL,
            requested_time TIMESTAMP NOT NULL,
            status TEXT DEFAULT 'pending',
            response_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES users (id),
            FOREIGN KEY (teacher_id) REFERENCES users (id)
        )
        ''')

        # Создаем администратора (id=0), если его нет
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


# Маршруты
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        db = get_db()
        try:
            hashed_password = generate_password_hash(password, method='sha256')
            db.execute(
                "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                (username, email, hashed_password, role)
            )
            db.commit()
            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Это имя пользователя или email уже заняты', 'danger')

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
            flash('Вы успешно вошли в систему', 'success')
            return redirect(url_for('dashboard'))

        flash('Неверное имя пользователя или пароль', 'danger')

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
        flash('Только ученики могут отправлять запросы', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        teacher_username = request.form['teacher']
        topic = request.form['topic']
        requested_time = request.form['requested_time']

        teacher = query_db('SELECT id FROM users WHERE username = ? AND role = ?',
                           [teacher_username, 'teacher'], one=True)

        if not teacher:
            flash('Учитель не найден', 'danger')
            return redirect(url_for('request_lesson'))

        db = get_db()
        db.execute('''
        INSERT INTO lesson_requests (student_id, teacher_id, topic, requested_time)
        VALUES (?, ?, ?, ?)
        ''', [session['user_id'], teacher['id'], topic, requested_time])
        db.commit()

        flash('Запрос отправлен учителю', 'success')
        return redirect(url_for('dashboard'))

    teachers = query_db("SELECT username FROM users WHERE role = 'teacher'")
    return render_template('request_lesson.html', teachers=teachers)


@app.route('/teacher-requests')
def teacher_requests():
    if 'user_id' not in session or session['role'] != 'teacher':
        flash('Только учителя могут просматривать запросы', 'danger')
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
        flash('Только учителя могут отвечать на запросы', 'danger')
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

    flash('Запрос обновлен', 'success')
    return redirect(url_for('teacher_requests'))


@app.route('/admin')
def admin_panel():
    if 'user_id' not in session or session['user_id'] != 0:
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('dashboard'))

    users = query_db("SELECT * FROM users WHERE id != 0")
    return render_template('admin_panel.html', users=users)


@app.route('/update-role/<int:user_id>', methods=['POST'])
def update_role(user_id):
    if 'user_id' not in session or session['user_id'] != 0:
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('dashboard'))

    new_role = request.form['role']

    if new_role not in ['teacher', 'student']:
        flash('Некорректная роль', 'danger')
        return redirect(url_for('admin_panel'))

    db = get_db()
    db.execute("UPDATE users SET role = ? WHERE id = ?", [new_role, user_id])
    db.commit()

    flash('Роль пользователя обновлена', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/delete-user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session['user_id'] != 0:
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('dashboard'))

    db = get_db()

    # Удаляем связанные запросы
    db.execute("DELETE FROM lesson_requests WHERE student_id = ? OR teacher_id = ?",
               [user_id, user_id])

    # Удаляем пользователя
    db.execute("DELETE FROM users WHERE id = ?", [user_id])
    db.commit()

    flash('Пользователь удален', 'success')
    return redirect(url_for('admin_panel'))


if __name__ == '__main__':
    if not os.path.exists(app.config['DATABASE']):
        init_db()
    app.run(debug=True)