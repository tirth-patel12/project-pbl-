from flask import Flask, render_template, request, redirect, url_for, Response, session, flash, jsonify, abort, make_response
import sqlite3
import os
import csv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from io import TextIOWrapper
from collections import defaultdict
from functools import wraps
from utils.chart_data import prepare_chart_data  # Make sure this file exists

app = Flask(__name__)
app.secret_key = 'HardToGuessTheMovieStrangersThing'

DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'inventory.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --- Ensure tables exist at startup ---
def init_items_table():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT,
            quantity INTEGER NOT NULL DEFAULT 0,
            min_threshold INTEGER NOT NULL DEFAULT 0,
            unit TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def init_users_table():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_items_table()
init_users_table()

# --- Inventory CRUD operations ---
def fetch_items():
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM items ORDER BY id').fetchall()
    conn.close()
    return items

def fetch_low_stock_items():
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM items WHERE quantity < min_threshold ORDER BY id').fetchall()
    conn.close()
    return items

def add_item(name, category, quantity, min_threshold, unit):
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO items (name, category, quantity, min_threshold, unit) VALUES (?, ?, ?, ?, ?)',
        (name, category, quantity, min_threshold, unit)
    )
    conn.commit()
    conn.close()

def update_item(item_id, name, category, quantity, min_threshold, unit):
    conn = get_db_connection()
    conn.execute(
        'UPDATE items SET name = ?, category = ?, quantity = ?, min_threshold = ?, unit = ?, last_updated=CURRENT_TIMESTAMP WHERE id = ?',
        (name, category, quantity, min_threshold, unit, item_id)
    )
    conn.commit()
    conn.close()

def delete_item(item_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM items WHERE id = ?', (item_id,))
    conn.commit()
    conn.close()

ALLOWED_EXTENSIONS = {'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def fetch_categories():
    conn = get_db_connection()
    categories = conn.execute('SELECT DISTINCT category FROM items WHERE category IS NOT NULL AND category != ""').fetchall()
    conn.close()
    return [c['category'] for c in categories]

# ---------- User Authentication ----------
def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    conn.close()
    return user

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        if get_user_by_username(username):
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()

        flash('Registration successful! You can log in now.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = get_user_by_username(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'Welcome {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    user = get_user_by_id(session['user_id'])
    return render_template('profile.html', user=user)

# ----------- Main Routes (Dashboard etc.) -----------
@app.route('/')
@login_required
def dashboard():
    category_filter = request.args.get('category', None)
    search_query = request.args.get('search', '').strip()
    sort_col = request.args.get('sort', 'id')
    sort_dir = request.args.get('direction', 'asc').lower()
    if sort_dir not in ['asc', 'desc']:
        sort_dir = 'asc'

    conn = get_db_connection()

    base_query = 'SELECT * FROM items WHERE 1=1'
    params = []

    if category_filter:
        base_query += ' AND category = ?'
        params.append(category_filter)

    if search_query:
        base_query += ' AND (name LIKE ? OR category LIKE ?)'

        like_query = f'%{search_query}%'
        params.extend([like_query, like_query])

    allowed_sort_cols = {'id', 'name', 'category', 'quantity', 'unit', 'min_threshold', 'last_updated'}
    if sort_col not in allowed_sort_cols:
        sort_col = 'id'

    base_query += f' ORDER BY {sort_col} {sort_dir}'

    items = conn.execute(base_query, params).fetchall()
    low_stock_items = [item for item in items if item['quantity'] < item['min_threshold']]
    categories = conn.execute(
        'SELECT DISTINCT category FROM items WHERE category IS NOT NULL AND category != ""'
    ).fetchall()
    categories = [c['category'] for c in categories]

    conn.close()

    chart_data = prepare_chart_data(items)

    return render_template(
        'index.html',
        items=items,
        alerts=low_stock_items,
        categories=categories,
        selected_category=category_filter,
        search_query=search_query,
        sort_col=sort_col,
        sort_dir=sort_dir,
        **chart_data
    )

@app.route('/low_stock')
@login_required
def low_stock():
    items = fetch_low_stock_items()
    return render_template('low_stock.html', items=items)

@app.route('/report')
@login_required
def report():
    items = fetch_items()
    return render_template('report.html', items=items)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        add_item(
            request.form['name'],
            request.form['category'],
            int(request.form['quantity']),
            int(request.form['min_threshold']),
            request.form.get('unit', '')
        )
        flash('Item added successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_item.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    conn = get_db_connection()
    item = conn.execute('SELECT * FROM items WHERE id=?', (id,)).fetchone()
    conn.close()
    if not item:
        flash('Item not found.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        update_item(
            id,
            request.form['name'],
            request.form['category'],
            int(request.form['quantity']),
            int(request.form['min_threshold']),
            request.form.get('unit', '')
        )
        flash('Item updated successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_item.html', item=item)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    delete_item(id)
    flash('Item deleted successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/export_csv')
@login_required
def export_csv():
    items = fetch_items()

    def generate():
        data = []
        header = ['ID', 'Name', 'Category', 'Quantity', 'Unit', 'Min Threshold', 'Last Updated']
        data.append(','.join(header) + '\n')
        for item in items:
            row = [
                str(item['id']),
                item['name'],
                item['category'] if item['category'] else '',
                str(item['quantity']),
                item['unit'] if item['unit'] else '',
                str(item['min_threshold']),
                item['last_updated'] if item['last_updated'] else ''
            ]
            data.append(','.join(row) + '\n')
        return data

    return Response(''.join(generate()), mimetype='text/csv',
                    headers={"Content-Disposition": "attachment;filename=inventory.csv"})

@app.route('/import_csv', methods=['GET', 'POST'])
@login_required
def import_csv():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part in the request.', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            stream = TextIOWrapper(file.stream, encoding='utf-8')
            csv_reader = csv.DictReader(stream)
            count = 0
            for row in csv_reader:
                # Normalize keys for case-insensitivity
                row = {k.strip().lower(): v for k, v in row.items()}
                name = row.get('name', '').strip()
                category = row.get('category', '').strip()
                quantity_str = row.get('quantity', '0').strip()
                min_threshold_str = row.get('min threshold', '0').strip()
                unit = row.get('unit', '').strip()

                try:
                    quantity = int(quantity_str) if quantity_str else 0
                    min_threshold = int(min_threshold_str) if min_threshold_str else 0
                except ValueError:
                    continue

                if name:
                    add_item(name, category, quantity, min_threshold, unit)
                    count += 1
            flash(f'Successfully imported {count} items.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type. Only CSV allowed.', 'danger')
            return redirect(request.url)
    return render_template('import_csv.html')

@app.route('/purchase', methods=['GET', 'POST'])
@login_required
def purchase():
    message = None
    if request.method == 'POST':
        item_id = request.form.get('item_id')
        quantity_to_remove = request.form.get('quantity', 1)
        try:
            item_id = int(item_id)
            quantity_to_remove = int(quantity_to_remove)
            if quantity_to_remove <= 0:
                message = "Quantity must be at least 1."
            else:
                conn = get_db_connection()
                item = conn.execute('SELECT * FROM items WHERE id = ?', (item_id,)).fetchone()
                if not item:
                    message = f"Item with ID {item_id} not found."
                elif item['quantity'] < quantity_to_remove:
                    message = f"Not enough stock. Current quantity: {item['quantity']}."
                else:
                    new_quantity = item['quantity'] - quantity_to_remove
                    if new_quantity > 0:
                        conn.execute('UPDATE items SET quantity = ?, last_updated=CURRENT_TIMESTAMP WHERE id = ?', (new_quantity, item_id))
                    else:
                        conn.execute('DELETE FROM items WHERE id = ?', (item_id,))
                    conn.commit()
                    message = f"Purchased {quantity_to_remove} unit(s) of '{item['name']}'."
                conn.close()
        except (ValueError, TypeError):
            message = "Invalid item ID or quantity value."
    return render_template('purchase.html', message=message)

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    app.run(debug=True)
