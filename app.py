from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from flask import Response
from functools import wraps
from datetime import datetime, timedelta
from flask import make_response
from xhtml2pdf import pisa
from io import BytesIO
import os
from werkzeug.utils import secure_filename
import qrcode
from io import BytesIO
import random
from flask import send_file, url_for

app = Flask(__name__)
app.secret_key = "masart_secret_key_123"

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

DATABASE = "database.db"

# -------------------------
# Database Setup
# -------------------------
def get_db_connection():
    conn = sqlite3.connect(DATABASE, timeout=10)  # Added timeout to avoid database lock errors
    conn.row_factory = sqlite3.Row  # This allows us to access columns by name
    return conn

# -------------------------
# Initialize Database
# -------------------------
def init_db():
    from werkzeug.security import generate_password_hash

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        # ---------------- Users table ----------------
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'staff'
            )
        ''')

        # ---------------- Inventory table ----------------
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT UNIQUE NOT NULL,
                quantity INTEGER NOT NULL,
                price REAL NOT NULL
            )
        ''')

        # ---------------- Sales table ----------------
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                total_price REAL NOT NULL,
                date TEXT DEFAULT CURRENT_TIMESTAMP,
                customer_name TEXT NOT NULL,
                FOREIGN KEY(item_id) REFERENCES inventory(id)
            )
        ''')

        # ---------------- Expenses table ----------------
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                description TEXT,
                amount REAL NOT NULL,
                date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # ---------------- Income Categories table ----------------
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS income_categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        ''')

        # Insert default income categories if empty
        cursor.execute("SELECT COUNT(*) FROM income_categories")
        if cursor.fetchone()[0] == 0:
            default_income_categories = ['Sales', 'Services', 'Other']
            cursor.executemany(
                "INSERT INTO income_categories (name) VALUES (?)",
                [(c,) for c in default_income_categories]
            )

        # ---------------- Income table ----------------
        # Use 'category_id' referencing income_categories
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS income (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                description TEXT NOT NULL,
                amount REAL NOT NULL,
                category_id INTEGER NOT NULL,
                date TEXT DEFAULT CURRENT_TIMESTAMP,
                recorded_by TEXT,
                FOREIGN KEY(category_id) REFERENCES income_categories(id)
            )
        ''')

        # ---------------- Categories table ----------------
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        ''')

        # Insert default expense categories
        cursor.execute("SELECT COUNT(*) FROM categories")
        if cursor.fetchone()[0] == 0:
            default_categories = ['Utilities', 'Rent', 'Maintainus', 'Transport', 'Misc']
            cursor.executemany(
                "INSERT INTO categories (name) VALUES (?)",
                [(c,) for c in default_categories]
            )

        # Create default admin if no users exist
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            hashed_password = generate_password_hash("admin123")
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("admin", hashed_password, "admin")
            )

            print("\n✅ Default admin created:")
            print("   Username: admin")
            print("   Password: admin123\n")
# -------------------------
# Helper Functions
# -------------------------
def get_total_sales():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT SUM(total_price) FROM sales")
    total = cursor.fetchone()[0]
    conn.close()
    return total if total else 0

def get_total_expenses():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT SUM(amount) FROM expenses")
    total = cursor.fetchone()[0]
    conn.close()
    return total if total else 0

# -------------------------
# Helper Functions for Report Generation
# -------------------------
def get_sales_report(start_date, end_date):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT i.item_name, SUM(s.quantity) AS total_quantity, SUM(s.total_price) AS total_sales
        FROM sales s
        JOIN inventory i ON s.item_id = i.id
        WHERE s.date BETWEEN ? AND ?
        GROUP BY i.id
        ORDER BY total_sales DESC
    """, (start_date, end_date))
    report = cursor.fetchall()
    conn.close()
    return report

def get_expenses_report(start_date, end_date):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT category, SUM(amount) AS total_expense
        FROM expenses
        WHERE date BETWEEN ? AND ?
        GROUP BY category
        ORDER BY total_expense DESC
    """, (start_date, end_date))
    report = cursor.fetchall()
    conn.close()
    return report

# -------------------------
# Routes: Login & Logout
# -------------------------
@app.route('/')
def home():
    # Redirect logged-in users to dashboard, otherwise to login
    return redirect(url_for('dashboard')) if 'user' in session else redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, go to dashboard
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # Validate input
        if not username or not password:
            flash("Please enter both username and password.", "error")
            return render_template('login.html')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, password, role, status FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()
        except Exception as e:
            print("Database error during login:", e)
            flash("System error. Please try again.", "error")
            return render_template('login.html')

        # Check if user exists
        if user:
            # sqlite3.Row objects are dict-like, use indexing
            stored_password = user['password']
            account_status = user['status'] if 'status' in user.keys() else 'active'

            if account_status == 'frozen':
                flash("This account is temporarily frozen. Contact admin.", "error")
                return render_template('login.html')

            if check_password_hash(stored_password, password):
                # Login success
                session['user'] = user['username']
                session['role'] = user['role']
                flash(f"Welcome back, {user['username']}!", "success")
                return redirect(url_for('dashboard'))

        # Login failed
        flash("Invalid username or password.", "error")
        return render_template('login.html')

    # GET request
    return render_template('login.html')


@app.route('/logout')
def logout():
    # Remove session data
    session.pop('user', None)
    session.pop('role', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# -------------------------
# Create User
# -------------------------
@app.route('/create_user', methods=['GET', 'POST'])
@admin_required
def create_user():
    if session.get('role') != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()

        if not username or not password or not role:
            flash("All fields are required.", "error")
            return render_template('create_user.html')

        hashed_password = generate_password_hash(password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_password, role)
            )
            conn.commit()
            conn.close()

            flash(f"User {username} created successfully.", "success")
            return redirect(url_for('user_management'))

        except Exception as e:
            print("Error creating user:", e)
            flash("System error. Could not create user.", "error")
            return render_template('create_user.html')

    return render_template('create_user.html')


# -------------------------
# Change User Role
# -------------------------
@app.route('/change_role/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def change_role(user_id):
    if session.get('role') != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found.", "error")
        return redirect(url_for('user_management'))

    # Prevent changing own role
    if user['username'] == session.get('user'):
        flash("You cannot change your own role.", "error")
        return redirect(url_for('user_management'))

    if request.method == 'POST':
        new_role = request.form.get('role')
        if new_role not in ['admin', 'staff']:
            flash("Invalid role selected.", "error")
            return render_template('change_role.html', user=user)

        cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        conn.close()

        flash(f"Role updated for {user['username']}.", "success")
        return redirect(url_for('user_management'))

    return render_template('change_role.html', user=user)


# -------------------------
# Reset Password
# -------------------------
@app.route('/reset_password/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def reset_password(user_id):
    if session.get('role') != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found.", "error")
        return redirect(url_for('user_management'))

    if request.method == 'POST':
        new_password = request.form.get('password', '').strip()
        if not new_password:
            flash("Password cannot be empty.", "error")
            return render_template('reset_password.html', user=user)

        hashed_password = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
        conn.commit()
        conn.close()

        flash(f"Password reset for {user['username']}.", "success")
        return redirect(url_for('user_management'))

    return render_template('reset_password.html', user=user)

# -------------------------
# Freeze / Unfreeze User
# -------------------------
@app.route('/toggle_freeze/<int:user_id>', methods=['POST'])
@admin_required
def toggle_freeze(user_id):
    # Prevent freezing yourself
    if session['user_id'] == user_id:
        flash("You cannot freeze/unfreeze your own account.", "error")
        return redirect(url_for('user_management'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if user:
            new_status = 'active' if user['status'] == 'frozen' else 'frozen'
            cursor.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
            conn.commit()
            flash(f"User account status updated to {new_status}.", "success")
        conn.close()
    except Exception as e:
        print("Error toggling freeze:", e)
        flash("System error. Could not update status.", "error")

    return redirect(url_for('user_management'))

# -------------------------
# Delete User
# -------------------------
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if session.get('role') != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found.", "error")
        return redirect(url_for('user_management'))

    # Prevent deleting yourself
    if user['username'] == session.get('user'):
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('user_management'))

    # Prevent deleting last admin
    if user['role'] == 'admin':
        cursor.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
        admin_count = cursor.fetchone()[0]
        if admin_count <= 1:
            flash("Cannot delete the last admin.", "error")
            return redirect(url_for('user_management'))

    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    flash("User deleted successfully.", "success")
    return redirect(url_for('user_management'))


# -------------------------
# User Management (View Users)
# -------------------------
@app.route('/user_management')
@admin_required
def user_management():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, status FROM users")  # include status
    users = cursor.fetchall()
    conn.close()
    return render_template('user_management.html', users=users)

# -------------------------
# Dashboard
# -------------------------
@app.route('/dashboard')
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    # ---------------- Total Sales ----------------
    cursor.execute("SELECT SUM(total_price) FROM sales")
    total_sales = cursor.fetchone()[0] or 0

    # ---------------- Total Expenses ----------------
    cursor.execute("SELECT SUM(amount) FROM expenses")
    total_expenses = cursor.fetchone()[0] or 0

    # ---------------- Total Income ----------------
    cursor.execute("SELECT SUM(amount) FROM income")
    total_income = cursor.fetchone()[0] or 0

    # ---------------- Net Profit ----------------
    net_profit = (total_sales + total_income) - total_expenses

    # ---------------- Monthly Sales Data ----------------
    cursor.execute("""
        SELECT strftime('%Y-%m', date) as month,
               SUM(total_price)
        FROM sales
        GROUP BY month
        ORDER BY month
    """)
    monthly_sales_data = cursor.fetchall()
    months = [row[0] for row in monthly_sales_data]
    sales_data = [row[1] for row in monthly_sales_data]

    # ---------------- Monthly Expenses Data ----------------
    cursor.execute("""
        SELECT strftime('%Y-%m', date) as month,
               SUM(amount)
        FROM expenses
        GROUP BY month
        ORDER BY month
    """)
    monthly_expenses_data = cursor.fetchall()
    expenses_dict = {row[0]: row[1] for row in monthly_expenses_data}
    expenses_data = [expenses_dict.get(month, 0) for month in months]  # align with months

    # ---------------- Monthly Income Data ----------------
    cursor.execute("""
        SELECT strftime('%Y-%m', date) as month,
               SUM(amount)
        FROM income
        GROUP BY month
        ORDER BY month
    """)
    monthly_income_data = cursor.fetchall()
    income_dict = {row[0]: row[1] for row in monthly_income_data}
    income_data = [income_dict.get(month, 0) for month in months]  # align with months

    # ---------------- Low Stock Items (<=5) ----------------
    cursor.execute("""
        SELECT item_name, quantity
        FROM inventory
        WHERE quantity <= 5
    """)
    low_stock = cursor.fetchall()

    conn.close()

    return render_template(
        'dashboard.html',
        user=session.get('user'),
        total_sales=total_sales,
        total_income=total_income,
        total_expenses=total_expenses,
        net_profit=net_profit,
        months=months,
        sales_data=sales_data,
        expenses_data=expenses_data,
        income_data=income_data,   # pass income_data for bar chart
        low_stock=low_stock
    )
# -------------------------
# Sales Module
# -------------------------
@app.route('/sales')
def view_sales():
    if 'user' not in session:
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.id,
                   i.item_name,
                   s.quantity,
                   s.total_price,
                   s.date
            FROM sales s
            JOIN inventory i ON s.item_id = i.id
            ORDER BY s.date DESC
        """)
        sales = cursor.fetchall()

    return render_template('sales.html', sales=sales)


@app.route('/add_sale', methods=['GET', 'POST'])
def add_sale():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch available items
    cursor.execute("SELECT id, item_name FROM inventory")
    items = cursor.fetchall()

    if request.method == 'POST':
        customer_name = request.form.get('customer_name', '').strip()
        product_id = request.form.get('product_id', '').strip()
        amount = request.form.get('amount', '').strip()

        if not customer_name or not product_id or not amount:
            flash("Please fill all required fields")
            return redirect(url_for('add_sale'))

        try:
            amount = float(amount)
        except ValueError:
            flash("Amount must be a number")
            return redirect(url_for('add_sale'))

        try:
            cursor.execute(
                "INSERT INTO sales (customer_name, item_id, quantity, total_price) VALUES (?, ?, ?, ?)",
                (customer_name, product_id, 1, amount)
            )
            conn.commit()
            flash("Sale added successfully!")
            return redirect(url_for('view_sales'))
        except Exception as e:
            flash(f"Error adding sale: {e}")
            return redirect(url_for('add_sale'))

    return render_template('add_sale.html', items=items)

# -------------------------------
# Delete Items in sales item
# -------------------------------
@app.route('/delete_sale/<int:sale_id>', methods=['POST'])
@admin_required
def delete_sale(sale_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Get sale details
        cursor.execute("SELECT item_id, quantity FROM sales WHERE id = ?", (sale_id,))
        sale = cursor.fetchone()

        if sale:
            item_id = sale['item_id']
            quantity = sale['quantity']

            # Restore inventory stock
            cursor.execute("""
                UPDATE inventory
                SET quantity = quantity + ?
                WHERE id = ?
            """, (quantity, item_id))

            # Delete sale
            cursor.execute("DELETE FROM sales WHERE id = ?", (sale_id,))
            conn.commit()

    flash("Sale deleted and stock restored!", "success")
    return redirect(url_for('view_sales'))


# -------------------------
# Clear sales 
# -------------------------
@app.route('/clear_sales', methods=['POST'])
@admin_required
def clear_sales():
    if 'user' not in session:
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sales")
        conn.commit()

    flash("All sales cleared!", "success")
    return redirect(url_for('view_sales'))


# ------------------------------
# Routes for Report Generation
# ------------------------------
@app.route('/generate_report', methods=['GET', 'POST'])
def generate_report():
    if 'user' not in session:
        return redirect(url_for('login'))

    report_type = request.form.get('report_type', 'daily')
    start_date = request.form.get('start_date', '')
    end_date = request.form.get('end_date', '')

    if request.method == 'POST':
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()

                # Handle the different report types
                if report_type == 'daily':
                    cursor.execute("""
                        SELECT i.item_name, s.quantity, s.total_price, s.date
                        FROM sales s
                        JOIN inventory i ON s.item_id = i.id
                        WHERE DATE(s.date) = DATE('now')
                    """)

                elif report_type == 'weekly':
                    cursor.execute("""
                        SELECT i.item_name, s.quantity, s.total_price, s.date
                        FROM sales s
                        JOIN inventory i ON s.item_id = i.id
                        WHERE s.date >= DATE('now', '-7 days')
                    """)

                elif report_type == 'monthly':
                    cursor.execute("""
                        SELECT i.item_name, s.quantity, s.total_price, s.date
                        FROM sales s
                        JOIN inventory i ON s.item_id = i.id
                        WHERE s.date >= DATE('now', 'start of month')
                    """)

                elif report_type == 'custom':
                    cursor.execute("""
                        SELECT i.item_name, s.quantity, s.total_price, s.date
                        FROM sales s
                        JOIN inventory i ON s.item_id = i.id
                        WHERE s.date BETWEEN ? AND ?
                    """, (start_date, end_date))

                sales_data = cursor.fetchall()

                # Generate the report page
                return render_template('report.html', sales_data=sales_data, report_type=report_type)

        except Exception as e:
            flash(f"Error generating report: {e}")
            return redirect(url_for('generate_report'))

    return render_template('generate_report.html')

# ------------------------------
# Routes for Report download
# ------------------------------
# ------------------------------
# Route: Download Sales Report PDF
# ------------------------------
@app.route('/download_report_pdf/<report_type>', methods=['GET'])
def download_report_pdf(report_type):
    # Ensure user is logged in
    if 'user' not in session:
        return "Access denied: Please log in first.", 403

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Fetch sales data
            if report_type == 'daily':
                cursor.execute("""
                    SELECT i.item_name, s.quantity, s.total_price, s.date
                    FROM sales s
                    JOIN inventory i ON s.item_id = i.id
                    WHERE DATE(s.date) = DATE('now')
                """)
            elif report_type == 'weekly':
                cursor.execute("""
                    SELECT i.item_name, s.quantity, s.total_price, s.date
                    FROM sales s
                    JOIN inventory i ON s.item_id = i.id
                    WHERE s.date >= DATE('now', '-7 days')
                """)
            elif report_type == 'monthly':
                cursor.execute("""
                    SELECT i.item_name, s.quantity, s.total_price, s.date
                    FROM sales s
                    JOIN inventory i ON s.item_id = i.id
                    WHERE s.date >= DATE('now', 'start of month')
                """)
            else:
                return "Invalid report type", 400

            sales_data = cursor.fetchall()

        # Generate unique report ID
        report_id = f"MAS-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000,9999)}"

        # Absolute paths
        logo_path = os.path.join(app.root_path, 'static', 'assets', 'logo.png')
        signature_path = os.path.join(app.root_path, 'static', 'signatures', 'authorized_signature.png')

        # Generate QR code
        verification_url = f"https://yourdomain.com/verify/{report_id}"
        qr_img = qrcode.make(verification_url)
        qr_folder = os.path.join(app.root_path, 'static', 'qr')
        os.makedirs(qr_folder, exist_ok=True)
        qr_path = os.path.join(qr_folder, f'{report_id}.png')
        qr_img.save(qr_path)

        # Render PDF template
        rendered = render_template(
            'report_pdf.html',
            sales_data=sales_data,
            report_type=report_type,
            report_id=report_id,
            current_date=datetime.now().strftime("%d %B %Y"),
            logo_path=logo_path,
            qr_code=qr_path,
            signature_image=signature_path if os.path.exists(signature_path) else ""
        )

        # Generate PDF
        pdf_bytes = BytesIO()
        pisa_status = pisa.CreatePDF(rendered, dest=pdf_bytes)
        pdf_bytes.seek(0)

        if pisa_status.err:
            return f"PDF generation failed: {pisa_status.err}", 500

        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={"Content-Disposition": f'attachment;filename=sales_report_{report_id}.pdf'}
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Exception during PDF generation: {e}", 500

# --------------------------------
# Route to mark an item as sold
# --------------------------------

@app.route('/mark_item_sold/<int:item_id>', methods=['POST'])
def mark_item_sold(item_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    quantity_sold = int(request.form['quantity'])
    customer_name = request.form['customer_name'].strip()

    if not customer_name:
        flash("Please provide the customer name.", "error")
        return redirect(url_for('view_inventory'))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Fetch current item quantity
        cursor.execute("SELECT quantity, price FROM inventory WHERE id = ?", (item_id,))
        item = cursor.fetchone()
        if not item or item['quantity'] < quantity_sold:
            flash("Not enough stock available.", "error")
            return redirect(url_for('view_inventory'))

        # Deduct the sold quantity from inventory
        new_quantity = item['quantity'] - quantity_sold
        cursor.execute("""
            UPDATE inventory
            SET quantity = ?
            WHERE id = ?
        """, (new_quantity, item_id))

        # Insert sale record
        cursor.execute("""
            INSERT INTO sales (item_id, quantity, total_price, customer_name, date)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (item_id, quantity_sold, quantity_sold * item['price'], customer_name))

        conn.commit()

    flash("Item marked as sold successfully!", "success")
    return redirect(url_for('view_inventory'))

# -------------------------
# Expenses Module
# -------------------------
@app.route('/expenses')
def view_expenses():
    if 'user' not in session:
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM expenses ORDER BY date DESC")
        expenses_list = cursor.fetchall()
    return render_template('expenses.html', expenses=expenses_list)

@app.route('/add_expense', methods=['GET', 'POST'])
def add_expense():
    if 'user' not in session:
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM categories")
        categories = [row['name'] for row in cursor.fetchall()]

    if request.method == 'POST':
        category = request.form.get('category', '').strip()
        description = request.form.get('description', '').strip()
        amount = request.form.get('amount', '').strip()

        if not category or not description or not amount:
            flash("Please fill all required fields", "error")
            return redirect(url_for('add_expense'))

        try:
            amount = float(amount)
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO expenses (category, description, amount, date)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (category, description, amount))
                conn.commit()
            flash("Expense added successfully!", "success")
            return redirect(url_for('view_expenses'))
        except Exception as e:
            flash(f"Error adding expense: {e}", "error")
            return redirect(url_for('add_expense'))

    return render_template('add_expense.html', categories=categories)


# -------------------------
# Edit Expense (Admin Only)
# -------------------------
@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@admin_required
def edit_expense(expense_id):

    # 🔐 Admin Protection
    if session.get('role') != 'admin':
        flash("Unauthorized action!", "danger")
        return redirect(url_for('view_expenses'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch expense first
    cursor.execute("SELECT * FROM expenses WHERE id = ?", (expense_id,))
    expense = cursor.fetchone()

    # If expense doesn't exist
    if not expense:
        conn.close()
        flash("Expense not found.", "danger")
        return redirect(url_for('view_expenses'))

    if request.method == 'POST':
        category = request.form['category']
        description = request.form['description']
        amount = request.form['amount']

        cursor.execute("""
            UPDATE expenses
            SET category = ?, description = ?, amount = ?
            WHERE id = ?
        """, (category, description, amount, expense_id))

        conn.commit()
        conn.close()

        flash("Expense updated successfully!", "success")
        return redirect(url_for('view_expenses'))

    conn.close()
    return render_template('edit_expense.html', expense=expense)

# -------------------------
# Delete Expense (Admin Only)
# -------------------------
@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@admin_required
def delete_expense(expense_id):

    if session.get('role') != 'admin':
        flash("Unauthorized action!", "danger")
        return redirect(url_for('view_expenses'))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM expenses WHERE id = ?", (expense_id,))
    conn.commit()
    conn.close()

    flash("Expense deleted successfully!", "success")
    return redirect(url_for('view_expenses'))

# -------------------------
# Inventory Module
# -------------------------
@app.route('/inventory', methods=['GET', 'POST'])
def view_inventory():
    if 'user' not in session:
        return redirect(url_for('login'))

    search_term = request.args.get('search_term', '').strip()

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Modify the SQL query to filter by search term
        if search_term:
            cursor.execute("""
                SELECT * FROM inventory
                WHERE item_name LIKE ?
                ORDER BY item_name
            """, ('%' + search_term + '%',))  # This will match any item names that contain the search term
        else:
            cursor.execute("SELECT * FROM inventory ORDER BY item_name")

        items = cursor.fetchall()

    return render_template('inventory.html', items=items)



@app.route('/add_inventory', methods=['GET', 'POST'])
def add_inventory():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        item_name = request.form.get('item_name', '').strip()
        quantity = request.form.get('quantity', '').strip()
        price = request.form.get('price', '').strip()

        if not item_name or not quantity or not price:
            flash("Please fill all required fields", "error")
            return redirect(url_for('add_inventory'))

        try:
            quantity = int(quantity)
            price = float(price)
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO inventory (item_name, quantity, price)
                    VALUES (?, ?, ?)
                """, (item_name, quantity, price))
                conn.commit()
            flash("Inventory item added successfully!", "success")
            return redirect(url_for('view_inventory'))
        except Exception as e:
            flash(f"Error adding inventory: {e}", "error")
            return redirect(url_for('add_inventory'))

    return render_template('add_inventory.html')

# -----------------------------------
# Delete item in Inventory Module
# -----------------------------------
@app.route('/delete_inventory/<int:item_id>', methods=['POST'])
@admin_required
def delete_inventory(item_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Delete related sales first (to avoid foreign key error)
        cursor.execute("DELETE FROM sales WHERE item_id = ?", (item_id,))
        cursor.execute("DELETE FROM inventory WHERE id = ?", (item_id,))
        conn.commit()

    flash("Inventory item deleted successfully!", "success")
    return redirect(url_for('view_inventory'))

# -----------------------------------
# Add income
# -----------------------------------
@app.route('/add_income', methods=['GET', 'POST'])
def add_income():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get all categories for the dropdown
    cursor.execute("SELECT id, name FROM income_categories ORDER BY name")
    categories = cursor.fetchall()

    if request.method == 'POST':
        description = request.form['description']
        amount = float(request.form['amount'])
        category_id = int(request.form['category_id'])
        recorded_by = session.get('user')

        cursor.execute(
            "INSERT INTO income (description, amount, category_id, recorded_by) VALUES (?, ?, ?, ?)",
            (description, amount, category_id, recorded_by)
        )
        conn.commit()
        conn.close()
        flash('Income record added successfully!', 'success')
        return redirect(url_for('view_income'))

    conn.close()
    return render_template('add_income.html', categories=categories)

# -----------------------------------
# View income
# -----------------------------------
@app.route('/view_income')
def view_income():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Join with categories to get the category name
    cursor.execute("""
        SELECT i.id, i.description, i.amount, c.name as category_name, i.date, i.recorded_by
        FROM income i
        JOIN income_categories c ON i.category_id = c.id
        ORDER BY i.date DESC
    """)
    incomes = cursor.fetchall()
    conn.close()

    return render_template('view_income.html', incomes=incomes)


# -----------------------------------
# View income
# -----------------------------------
UPLOAD_FOLDER = 'static/signatures'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/upload-signature', methods=['GET', 'POST'])
def upload_signature():
    if request.method == 'POST':
        file = request.files['signature']
        if file:
            filename = secure_filename("authorized_signature.png")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash("Signature uploaded successfully!", "success")
    return render_template("upload_signature.html")

# -------------------------
# Run App
# -------------------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
    