import hashlib
import mysql.connector
from functools import wraps
from flask import session
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # For session management

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)



def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session:
                flash("You need to log in first.", "error")
                return redirect(url_for('login'))
            if session['role'] not in allowed_roles:
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for('login'))
                # return redirect(url_for('dashboard'))  # Redirect to a general dashboard
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def dashboard():
    return render_template('dashboard.html', username=current_user.username, role=current_user.role)


# Database connection
def get_db_connection():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Login!@12",
        database="credit_card_vault"
    )
    return conn

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role




# Load user from database
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'], user['role'])
    return None

# Home route
@app.route('/')
def home():
    return redirect(url_for('login'))

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        name = request.form['name']
        email = request.form['email']

        # Hash the password using SHA-2 (SHA-256)
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # AES Encryption key 
        encryption_key = 'secret'

        # Database connection
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Insert into users table
            cursor.execute("INSERT INTO users (username, user_password, role) VALUES (%s, %s, %s)",
                           (username, hashed_password, role))
            conn.commit()

            user_id = cursor.lastrowid

            # Insert customer details only if the role is 'customer'
            if role == 'customer':
                # Insert into customers table
                cursor.execute("INSERT INTO customers (id, name, email) VALUES (%s, %s, %s)",
                               (user_id, name, email))
                conn.commit()

                # Retrieve and encrypt credit card details
                card_number = request.form.get('card_number')
                cvv = request.form.get('cvv')
                expiration_date = request.form.get('expiration_date')

                if card_number and cvv and expiration_date:
                    cursor.execute(f"""
                        INSERT INTO credit_card (customer_id, encrypted_card_number, encrypted_cvv, expiration_date) 
                        VALUES (%s, AES_ENCRYPT(%s, %s), AES_ENCRYPT(%s, %s), %s)
                        """, (user_id, card_number, encryption_key, cvv, encryption_key, expiration_date))
                    conn.commit()

            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))

        except mysql.connector.Error as err:
            flash(f'Error: {err}')
        finally:
            conn.close()

    return render_template('register.html')


# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and user['user_password'] == hashlib.sha256(password.encode()).hexdigest():
            user_obj = User(user['id'], user['username'], user['role'])
            login_user(user_obj)
            
            # Store user info in session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            
            # Role-based redirection
            role = user['role']
            if role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif role == 'finance':
                return redirect(url_for('finance_overview'))
            elif role == 'customer_service':
                return redirect(url_for('customer_service_dashboard'))
            elif role == 'customer':
                return redirect(url_for('payment'))
            else:
                flash('Unknown role. Please contact support.', 'error')
                return redirect(url_for('login'))
        
        else:
            flash('Invalid credentials. Please try again.')
            return redirect(url_for('login'))

    return render_template('login.html')

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username, role=current_user.role)

# Edit Profile
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    user_id = current_user.id

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Update password if provided
        if password:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            cursor.execute("UPDATE users SET user_password = %s WHERE id = %s", (hashed_password, user_id))

        cursor.execute("UPDATE customers SET name = %s, email = %s WHERE id = %s", (name, email, user_id))
        conn.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT name, email FROM customers WHERE id = %s", (user_id,))
    customer = cursor.fetchone()
    conn.close()

    return render_template('edit_profile.html', customer=customer)

# Payment Route
@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    if request.method == 'POST':
        amount = request.form['amount']
        customer_id = current_user.id

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM credit_card WHERE customer_id = %s", (customer_id,))
        credit_card = cursor.fetchone()
        
        if credit_card:
            credit_card_id = credit_card[0]
            
            # Insert transaction
            cursor.execute("INSERT INTO transactions (credit_card_id, amount) VALUES (%s, %s)",
                           (credit_card_id, amount))
            conn.commit()
            flash('Payment successful!')
        else:
            flash('No credit card found. Please update your profile.')

        conn.close()
    return render_template('payment.html')

@app.route('/admin_dashboard')
@role_required(['admin'])
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch admin data from the admin_dashboard view, including decrypted credit card details
    encryption_key = 'secret'
    query = f"""
        SELECT 
            c.id AS customer_id,
            c.name AS customer_name,
            c.email AS customer_email,
            t.id AS transaction_id,
            t.amount,
            t.timestamp,
            AES_DECRYPT(cc.encrypted_card_number, %s) AS card_number,
            AES_DECRYPT(cc.encrypted_cvv, %s) AS cvv,
            cc.expiration_date
        FROM 
            customers c
        LEFT JOIN 
            credit_card cc ON c.id = cc.customer_id
        LEFT JOIN 
            transactions t ON cc.id = t.credit_card_id;
    """
    cursor.execute(query, (encryption_key, encryption_key))
    admin_data = cursor.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', admin_data=admin_data)

@app.route('/finance_overview')
@role_required(['finance'])
def finance_overview():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch finance data from the finance_overview view
    cursor.execute("SELECT * FROM finance_overview")
    finance_data = cursor.fetchall()
    conn.close()

    return render_template('finance_overview.html', finance_data=finance_data)

@app.route('/customer_service_dashboard')
@role_required(['customer_service'])
def customer_service_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch customer service data (e.g., customers table)
    cursor.execute("SELECT * FROM customers")
    customer_data = cursor.fetchall()
    conn.close()

    return render_template('customer_service_dashboard.html', customer_data=customer_data)


# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000,ssl_context=('../server.crt', '../server.key'))
