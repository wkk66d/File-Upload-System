# main.py
from flask import Flask, request, jsonify, redirect, render_template, session, url_for, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime
import time
import re

UPLOAD_FOLDER = 'uploads'
MAX_UPLOAD_SIZE = 50 * 1024  # 10MB

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE * 2  # 服务器端限制
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)
DATABASE = 'users.db'

def create_table():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  is_admin BOOLEAN DEFAULT 0,
                  max_storage INTEGER DEFAULT 51200)''')
    
    admin_exists = c.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
    if not admin_exists:
        hashed_pw = generate_password_hash('Jayne?123')
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                 ('admin', hashed_pw))
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  filename TEXT NOT NULL,
                  stored_name TEXT NOT NULL UNIQUE,
                  size INTEGER NOT NULL,
                  upload_time DATETIME NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS banned_ips
                 (ip TEXT PRIMARY KEY,
                  ban_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                  reason TEXT)''')
    
    conn.commit()
    conn.close()

create_table()

banned_ips_cache = set()
last_refresh = 0

def refresh_banned_ips():
    global banned_ips_cache, last_refresh
    # 每5分钟刷新一次
    if time.time() - last_refresh > 300: 
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT ip FROM banned_ips")
        banned_ips_cache = {row[0] for row in c.fetchall()}
        conn.close()
        last_refresh = time.time()

def get_client_ip():
    """获取真实客户端IP"""
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr

@app.before_request
def check_banned():
    refresh_banned_ips()
    client_ip = get_client_ip()
    if client_ip in banned_ips_cache:
        abort(403, description="IP已被封禁")

def login_required(view):
    def wrapped_view(**kwargs):
        if not session.get('user_id'):
            return redirect(url_for('index'))
        return view(**kwargs)
    wrapped_view.__name__ = view.__name__
    return wrapped_view

def admin_required(view):
    def wrapped_view(**kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('index'))
        return view(**kwargs)
    wrapped_view.__name__ = view.__name__
    return wrapped_view

@app.route('/')
def index():
    if session.get('user_id'):
        return redirect('/welcome')
    return render_template('login.html')

@app.route('/index')
def defalut_index():
    return redirect('/')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Missing parameters'}), 400

    hashed_password = generate_password_hash(password)
    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                 (username, hashed_password))
        conn.commit()
        return jsonify({'success': True, 'message': 'Registration successful'})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Username exists'}), 400
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['is_admin'] = bool(user[3])
        return jsonify({'success': True, 'message': 'Login successful'})
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/welcome')
@login_required
def welcome():
    return render_template('welcome.html', username=session.get('username'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # 验证输入
        if not all([old_password, new_password, confirm_password]):
            return render_template('change_password.html', error='请填写所有字段')

        if new_password != confirm_password:
            return render_template('change_password.html', error='新密码不一致')

        # 验证旧密码
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        
        if not user or not check_password_hash(user[0], old_password):
            conn.close()
            return render_template('change_password.html', error='旧密码错误')

        # 更新密码
        hashed_pw = generate_password_hash(new_password)
        c.execute("UPDATE users SET password = ? WHERE id = ?", 
                 (hashed_pw, session['user_id']))
        conn.commit()
        conn.close()
        
        return redirect(url_for('welcome', msg='密码修改成功'))
    
    return render_template('change_password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/index')

@app.route('/files')
@login_required
def file_manager():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # 获取用户文件
    c.execute("SELECT * FROM files WHERE user_id = ?", (session['user_id'],))
    files = c.fetchall()
    
    # 获取存储使用情况（处理空值）
    c.execute("""
        SELECT 
            COALESCE(SUM(size), 0),
            (SELECT max_storage FROM users WHERE id = ?)
        FROM files 
        WHERE user_id = ?""", 
        (session['user_id'], session['user_id']))
    used, max_size = c.fetchone()
    
    conn.close()
    return render_template('files.html', 
                          files=files,
                          used=used,
                          max_size=max_size)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'Invalid filename'}), 400
    
    # 检查存储空间
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""
        SELECT 
            (SELECT SUM(size) FROM files WHERE user_id = ?) AS used,
            (SELECT max_storage FROM users WHERE id = ?) AS max_size
    """, (session['user_id'], session['user_id']))
    used, max_size = c.fetchone()
    used = used or 0
    
    if len(file.read()) > max_size - used:
        return jsonify({'success': False, 'message': 'Storage limit exceeded'}), 400
    file.seek(0)  # 重置文件指针
    
    # 生成唯一文件名
    ext = os.path.splitext(file.filename)[1]
    stored_name = f"{session['user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}{ext}"
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
    
    try:
        file.save(save_path)
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        
        c.execute("INSERT INTO files (user_id, filename, stored_name, size, upload_time) VALUES (?, ?, ?, ?, ?)",
                 (session['user_id'], file.filename, stored_name, file_size, datetime.now()))
        conn.commit()
        return jsonify({'success': True, 'message': 'Upload successful'})
    except Exception as e:
        if os.path.exists(save_path):
            os.remove(save_path)
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()

@app.route('/download/<file_id>')
@login_required
def download_file(file_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    file = c.fetchone()
    conn.close()

    # 管理员或文件所有者可下载
    if file and (session.get('is_admin') or file[1] == session['user_id']):
        return send_from_directory(app.config['UPLOAD_FOLDER'], 
                                 file[3], 
                                 as_attachment=True, 
                                 download_name=file[2])
    return redirect(url_for('file_manager'))

@app.route('/delete/<file_id>')
@login_required
def delete_file(file_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    file = c.fetchone()

    # 管理员或文件所有者可删除
    if file and (session.get('is_admin') or file[1] == session['user_id']):
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file[3])
            os.remove(file_path)
            c.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
        finally:
            conn.close()
    return redirect(url_for('admin_files' if session.get('is_admin') else 'file_manager'))

# 管理员功能

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # 修正的SQL查询（返回用户数据而非文件数据）
    c.execute('''SELECT 
                    u.id, 
                    u.username, 
                    COALESCE(SUM(f.size), 0) AS used,
                    u.max_storage 
                FROM users u
                LEFT JOIN files f ON u.id = f.user_id
                WHERE u.is_admin = 0
                GROUP BY u.id''')
    users = c.fetchall()
    
    conn.close()
    return render_template('admin_dashboard.html', users=users)  # 确保传递users变量

@app.route('/admin/update-password', methods=['POST'])
@admin_required
def admin_update_password():
    data = request.get_json()
    user_id = data.get('user_id')
    new_password = data.get('new_password')

    if not user_id or not new_password:
        return jsonify({'success': False, 'message': 'Missing parameters'}), 400

    hashed_pw = generate_password_hash(new_password)
    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_pw, user_id))
        conn.commit()
        return jsonify({'success': True, 'message': 'Password updated'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()

@app.route('/admin/delete-user', methods=['POST'])
@admin_required
def delete_user():
    user_id = request.get_json().get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Missing user ID'}), 400

    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return jsonify({'success': True, 'message': 'User deleted'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()
@app.route('/admin/files')
@admin_required
def admin_files():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''SELECT files.*, users.username 
               FROM files 
               JOIN users ON files.user_id = users.id''')
    files = c.fetchall()
    conn.close()
    return render_template('admin_files.html', files=files)

@app.route('/admin/files/<user_id>')
@admin_required
def admin_user_files(user_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    try:
        # 获取文件数据（添加显式类型转换）
        c.execute("""
            SELECT 
                id, 
                filename, 
                stored_name, 
                CAST(size AS INTEGER), 
                strftime('%Y-%m-%d %H:%M', upload_time)
            FROM files 
            WHERE user_id = ?
        """, (user_id,))
        files = c.fetchall()

        # 获取用户信息（添加类型转换和空值处理）
        c.execute("""
            SELECT 
                username, 
                CAST(max_storage AS INTEGER), 
                COALESCE((
                    SELECT SUM(CAST(size AS INTEGER)) 
                    FROM files WHERE user_id = ?
                ), 0)
            FROM users 
            WHERE id = ?
        """, (user_id, user_id))
        
        username, max_size, used = c.fetchone()
        
        return render_template('admin_files.html',
                             files=files,
                             username=username,
                             used=used,
                             max_size=max_size)
    
    except Exception as e:
        return f"Error: {str(e)}", 500
    finally:
        conn.close()

@app.route('/admin/set-limit', methods=['POST'])
@admin_required
def set_storage_limit():
    data = request.get_json()
    user_id = data.get('user_id')
    new_limit = data.get('limit')
    
    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("UPDATE users SET max_storage = ? WHERE id = ?", 
                 (new_limit, user_id))
        conn.commit()
        return jsonify({'success': True, 'message': 'Storage limit updated'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()

@app.route('/admin/delete-user-files/<user_id>', methods=['POST'])
@admin_required
def delete_user_files(user_id):
    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        
        # 获取所有文件记录
        c.execute("SELECT stored_name FROM files WHERE user_id = ?", (user_id,))
        files = c.fetchall()
        
        # 删除物理文件
        for file in files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file[0])
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # 删除数据库记录
        c.execute("DELETE FROM files WHERE user_id = ?", (user_id,))
        conn.commit()
        
        return jsonify({
            'success': True,
            'message': f'Deleted {len(files)} files'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()
        
@app.route('/admin/banned-ips')
@admin_required
def banned_ips():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT ip, ban_time, reason FROM banned_ips ORDER BY ban_time DESC")
    ips = c.fetchall()
    conn.close()
    return render_template('admin_banned_ips.html', ips=ips)

@app.route('/admin/ban-ip', methods=['POST'])
@admin_required
def ban_ip():
    ip = request.form['ip']
    reason = request.form.get('reason', '')

    # 验证IP格式
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return "无效的IP地址", 400

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO banned_ips (ip, reason) VALUES (?, ?)", 
                 (ip, reason))
        conn.commit()
        # 更新缓存
        banned_ips_cache.add(ip)
    except sqlite3.IntegrityError:
        return "该IP已被封禁", 400
    finally:
        conn.close()
    
    return redirect(url_for('banned_ips'))

@app.route('/admin/unban-ip/<ip>')
@admin_required
def unban_ip(ip):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("DELETE FROM banned_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()
    # 更新缓存
    if ip in banned_ips_cache:
        banned_ips_cache.remove(ip)
    return redirect(url_for('banned_ips'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')