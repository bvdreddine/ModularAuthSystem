import os
import json
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bootstrap import Bootstrap5
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
bootstrap = Bootstrap5(app)

# Configuration
AUTH_SERVICE_URL = "http://localhost:8000"  # Auth service URL
USER_SERVICE_URL = "http://localhost:8001"  # User service URL
MOCK_MODE = True  # Set to False when real services are available

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'token' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin role required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'token' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        
        if 'user_roles' not in session or 'admin' not in session['user_roles']:
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')
        
        try:
            if MOCK_MODE:
                # Mock authentication for development/testing
                if username == 'admin@example.com' and password == 'admin123':
                    session['token'] = 'mock-token'
                    session['user_info'] = {
                        'username': username,
                        'first_name': 'Admin',
                        'last_name': 'User'
                    }
                    session['user_roles'] = ['admin']
                    flash('Successfully logged in (MOCK MODE)!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid credentials (MOCK MODE)', 'danger')
            else:
                # Real authentication through Auth Service
                response = requests.post(
                    f"{AUTH_SERVICE_URL}/auth/token",
                    data={
                        "username": username,
                        "password": password,
                        "grant_type": "password",
                        "client_id": "auth-service",
                        "client_secret": "your-client-secret"  # Use environment variable in production
                    }
                )
                
                if response.status_code == 200:
                    token_data = response.json()
                    session['token'] = token_data.get('access_token')
                    
                    # Get user info from token
                    headers = {'Authorization': f'Bearer {session["token"]}'}
                    user_response = requests.get(f"{USER_SERVICE_URL}/users/me", headers=headers)
                    
                    if user_response.status_code == 200:
                        session['user_info'] = user_response.json()
                        
                        # Extract roles from token
                        token_validation = requests.post(
                            f"{AUTH_SERVICE_URL}/auth/validate",
                            json={"token": session['token']}
                        )
                        token_payload = token_validation.json()
                        session['user_roles'] = token_payload.get('realm_access', {}).get('roles', [])
                        
                        flash('Successfully logged in!', 'success')
                        return redirect(url_for('dashboard'))
                    else:
                        flash('Failed to get user information', 'danger')
                else:
                    flash('Invalid credentials', 'danger')
        except Exception as e:
            flash(f'Login error: {str(e)}', 'danger')
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if 'admin' in session.get('user_roles', []):
        return render_template('admin_dashboard.html')
    elif 'teacher' in session.get('user_roles', []):
        return render_template('teacher_dashboard.html')
    else:
        return render_template('student_dashboard.html')

@app.route('/profile')
@login_required
def profile():
    user_info = session.get('user_info', {})
    return render_template('profile.html', user=user_info)

@app.route('/users')
@admin_required
def users_list():
    try:
        if MOCK_MODE:
            # Mock user data for development/testing
            users = [
                {
                    'id': '1',
                    'first_name': 'Admin',
                    'last_name': 'User',
                    'email': 'admin@example.com',
                    'role': 'admin',
                    'active': True
                },
                {
                    'id': '2',
                    'first_name': 'Teacher',
                    'last_name': 'One',
                    'email': 'teacher1@example.com',
                    'role': 'teacher',
                    'active': True
                },
                {
                    'id': '3',
                    'first_name': 'Student',
                    'last_name': 'One',
                    'email': 'student1@example.com',
                    'role': 'student',
                    'active': True
                }
            ]
            pagination = {
                'total': 3,
                'page': 1,
                'size': 10
            }
        else:
            # Real user data from User Service
            headers = {'Authorization': f'Bearer {session["token"]}'}
            response = requests.get(
                f"{USER_SERVICE_URL}/users",
                headers=headers,
                params={'page': request.args.get('page', 1), 'size': request.args.get('size', 10)}
            )
            
            if response.status_code == 200:
                data = response.json()
                users = data.get('users', [])
                pagination = {
                    'total': data.get('total', 0),
                    'page': data.get('page', 1),
                    'size': data.get('size', 10)
                }
            else:
                flash('Failed to retrieve users', 'danger')
                return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Error retrieving users: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
        
    return render_template('users.html', users=users, pagination=pagination)

@app.route('/users/new', methods=['GET', 'POST'])
@admin_required
def create_user():
    if request.method == 'POST':
        user_data = {
            'first_name': request.form.get('first_name'),
            'last_name': request.form.get('last_name'),
            'email': request.form.get('email'),
            'password': request.form.get('password'),
            'role': request.form.get('role'),
            'department': request.form.get('department'),
            'phone': request.form.get('phone'),
            'active': True if request.form.get('active') == 'on' else False
        }
        
        try:
            if MOCK_MODE:
                # Mock user creation for development/testing
                flash('User created successfully (MOCK MODE)!', 'success')
                return redirect(url_for('users_list'))
            else:
                # Real user creation through User Service
                headers = {'Authorization': f'Bearer {session["token"]}'}
                response = requests.post(
                    f"{USER_SERVICE_URL}/users",
                    json=user_data,
                    headers=headers
                )
                
                if response.status_code == 201:
                    flash('User created successfully!', 'success')
                    return redirect(url_for('users_list'))
                else:
                    error_message = response.json().get('detail', 'Failed to create user')
                    flash(error_message, 'danger')
        except Exception as e:
            flash(f'Error creating user: {str(e)}', 'danger')
    
    return render_template('user_form.html', user=None, action='create')

@app.route('/users/edit/<user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    if request.method == 'POST':
        user_data = {
            'first_name': request.form.get('first_name'),
            'last_name': request.form.get('last_name'),
            'email': request.form.get('email'),
            'role': request.form.get('role'),
            'department': request.form.get('department'),
            'phone': request.form.get('phone'),
            'active': True if request.form.get('active') == 'on' else False
        }
        
        try:
            if MOCK_MODE:
                # Mock user update for development/testing
                flash('User updated successfully (MOCK MODE)!', 'success')
                return redirect(url_for('users_list'))
            else:
                # Real user update through User Service
                headers = {'Authorization': f'Bearer {session["token"]}'}
                response = requests.put(
                    f"{USER_SERVICE_URL}/users/{user_id}",
                    json=user_data,
                    headers=headers
                )
                
                if response.status_code == 200:
                    flash('User updated successfully!', 'success')
                    return redirect(url_for('users_list'))
                else:
                    error_message = response.json().get('detail', 'Failed to update user')
                    flash(error_message, 'danger')
        except Exception as e:
            flash(f'Error updating user: {str(e)}', 'danger')
            
    try:
        if MOCK_MODE:
            # Mock user data for development/testing
            if user_id == '1':
                user = {
                    'id': '1',
                    'first_name': 'Admin',
                    'last_name': 'User',
                    'email': 'admin@example.com',
                    'role': 'admin',
                    'department': 'IT',
                    'phone': '123-456-7890',
                    'active': True
                }
            elif user_id == '2':
                user = {
                    'id': '2',
                    'first_name': 'Teacher',
                    'last_name': 'One',
                    'email': 'teacher1@example.com',
                    'role': 'teacher',
                    'department': 'Math',
                    'phone': '123-456-7891',
                    'active': True
                }
            else:
                user = {
                    'id': '3',
                    'first_name': 'Student',
                    'last_name': 'One',
                    'email': 'student1@example.com',
                    'role': 'student',
                    'department': 'Math',
                    'phone': '123-456-7892',
                    'active': True
                }
        else:
            # Real user data from User Service
            headers = {'Authorization': f'Bearer {session["token"]}'}
            response = requests.get(
                f"{USER_SERVICE_URL}/users/{user_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                user = response.json()
            else:
                flash('User not found', 'danger')
                return redirect(url_for('users_list'))
    except Exception as e:
        flash(f'Error retrieving user: {str(e)}', 'danger')
        return redirect(url_for('users_list'))
        
    return render_template('user_form.html', user=user, action='edit')

@app.route('/users/delete/<user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    try:
        if MOCK_MODE:
            # Mock user deletion for development/testing
            flash('User deleted successfully (MOCK MODE)!', 'success')
        else:
            # Real user deletion through User Service
            headers = {'Authorization': f'Bearer {session["token"]}'}
            response = requests.delete(
                f"{USER_SERVICE_URL}/users/{user_id}",
                headers=headers
            )
            
            if response.status_code == 204:
                flash('User deleted successfully!', 'success')
            else:
                error_message = response.json().get('detail', 'Failed to delete user')
                flash(error_message, 'danger')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'danger')
        
    return redirect(url_for('users_list'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)