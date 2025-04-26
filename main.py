import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

# Charger les variables d'environnement depuis le fichier .env
load_dotenv()

print("Variables d'environnement chargées")
print(f"DATABASE_URL = {os.environ.get('DATABASE_URL')}")
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from functools import wraps
from models import db, User, Course, Enrollment

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
# Utiliser SQLite directement sans dépendre des variables d'environnement
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///modular_auth_system.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

bootstrap = Bootstrap(app)
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Configuration
AUTH_SERVICE_URL = "http://localhost:8000"  # Auth service URL
USER_SERVICE_URL = "http://localhost:8001"  # User service URL
MOCK_MODE = True  # Set to False when real services are available

# Create database tables
with app.app_context():
    db.create_all()

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

# Initialize database with default users if empty
def create_default_users():
    """Create default users, courses, and enrollments if none exist."""
    # Check if any users exist
    user_count = User.query.count()
    if user_count == 0:
        # Create default admin user
        admin = User(
            first_name='Admin',
            last_name='User',
            email='admin@example.com',
            role='admin',
            department='IT',
            phone='123-456-7890',
            active=True
        )
        admin.set_password('admin123')
        
        # Create default teacher user
        teacher = User(
            first_name='Teacher',
            last_name='One',
            email='teacher1@example.com',
            role='teacher',
            department='Math',
            phone='123-456-7891',
            active=True
        )
        teacher.set_password('teacher123')
        
        # Create default student user
        student = User(
            first_name='Student',
            last_name='One',
            email='student1@example.com',
            role='student',
            department='Math',
            phone='123-456-7892',
            active=True
        )
        student.set_password('student123')
        
        # Add users to database
        db.session.add(admin)
        db.session.add(teacher)
        db.session.add(student)
        db.session.commit()
        
        # Create default courses
        math_course = Course(
            title='Introduction to Mathematics',
            description='Learn the fundamentals of mathematics',
            teacher_id=teacher.id,
            department='Math',
            active=True
        )
        
        physics_course = Course(
            title='Physics 101',
            description='Discover the principles of physics',
            teacher_id=teacher.id,
            department='Science',
            active=True
        )
        
        cs_course = Course(
            title='Computer Science Basics',
            description='Introduction to programming and algorithms',
            teacher_id=teacher.id,
            department='Computer Science',
            active=True
        )
        
        # Add courses to database
        db.session.add(math_course)
        db.session.add(physics_course)
        db.session.add(cs_course)
        db.session.commit()
        
        # Enroll student in courses
        math_enrollment = Enrollment(
            student_id=student.id,
            course_id=math_course.id,
            status='active'
        )
        
        physics_enrollment = Enrollment(
            student_id=student.id,
            course_id=physics_course.id,
            status='active'
        )
        
        cs_enrollment = Enrollment(
            student_id=student.id,
            course_id=cs_course.id,
            status='active'
        )
        
        # Add enrollments to database
        db.session.add(math_enrollment)
        db.session.add(physics_enrollment)
        db.session.add(cs_enrollment)
        db.session.commit()

# Fonction pour initialiser les tables et les données par défaut
def init_db():
    with app.app_context():
        db.create_all()
        create_default_users()

# Exécuter l'initialisation de la base de données
init_db()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('username')  # Form field is named 'username' but contains email
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required', 'danger')
            return render_template('login.html')
        
        try:
            if MOCK_MODE:
                # Database authentication instead of microservices
                user = User.query.filter_by(email=email).first()
                
                if user and user.check_password(password):
                    # Login user with Flask-Login
                    login_user(user)
                    
                    # Store info in session for compatibility with old code
                    session['token'] = 'database-auth-token'
                    session['user_info'] = user.to_dict()
                    session['user_roles'] = [user.role]
                    
                    flash(f'Welcome back, {user.first_name}!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid credentials', 'danger')
            else:
                # Real authentication through Auth Service
                response = requests.post(
                    f"{AUTH_SERVICE_URL}/auth/token",
                    data={
                        "username": email,
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
                        user_data = user_response.json()
                        session['user_info'] = user_data
                        
                        # Extract roles from token
                        token_validation = requests.post(
                            f"{AUTH_SERVICE_URL}/auth/validate",
                            json={"token": session['token']}
                        )
                        token_payload = token_validation.json()
                        session['user_roles'] = token_payload.get('realm_access', {}).get('roles', [])
                        
                        # Also update or create user in local database
                        user = User.query.filter_by(email=email).first()
                        if not user:
                            user = User(
                                email=email,
                                first_name=user_data.get('first_name', ''),
                                last_name=user_data.get('last_name', ''),
                                role=user_data.get('role', 'student'),
                                department=user_data.get('department', ''),
                                phone=user_data.get('phone', ''),
                                active=user_data.get('active', True),
                                keycloak_id=user_data.get('id', '')
                            )
                            db.session.add(user)
                            db.session.commit()
                        
                        # Login user with Flask-Login
                        login_user(user)
                        
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
    logout_user()  # Flask-Login logout
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
        page = int(request.args.get('page', 1))
        size = int(request.args.get('size', 10))
        
        if MOCK_MODE:
            # Get users from database
            users_query = User.query.order_by(User.created_at.desc())
            
            # Get total count
            total = users_query.count()
            
            # Paginate
            offset = (page - 1) * size
            users_paginated = users_query.offset(offset).limit(size).all()
            
            # Convert to dict
            users = [user.to_dict() for user in users_paginated]
            
            pagination = {
                'total': total,
                'page': page,
                'size': size
            }
        else:
            # Real user data from User Service
            headers = {'Authorization': f'Bearer {session["token"]}'}
            response = requests.get(
                f"{USER_SERVICE_URL}/users",
                headers=headers,
                params={'page': page, 'size': size}
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
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        department = request.form.get('department')
        phone = request.form.get('phone')
        active = True if request.form.get('active') == 'on' else False
        
        try:
            if MOCK_MODE:
                # Check if user already exists
                existing_user = User.query.filter_by(email=email).first()
                if existing_user:
                    flash('A user with this email already exists', 'danger')
                    return render_template('user_form.html', user=None, action='create')
                
                # Create user in database
                new_user = User(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    role=role,
                    department=department,
                    phone=phone,
                    active=active
                )
                new_user.set_password(password)
                
                db.session.add(new_user)
                db.session.commit()
                
                flash('User created successfully!', 'success')
                return redirect(url_for('users_list'))
            else:
                # Prepare data for User Service
                user_data = {
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': email,
                    'password': password,
                    'role': role,
                    'department': department,
                    'phone': phone,
                    'active': active
                }
                
                # Real user creation through User Service
                headers = {'Authorization': f'Bearer {session["token"]}'}
                response = requests.post(
                    f"{USER_SERVICE_URL}/users",
                    json=user_data,
                    headers=headers
                )
                
                if response.status_code == 201:
                    # Also create user in local database
                    user_response = response.json()
                    new_user = User(
                        first_name=first_name,
                        last_name=last_name,
                        email=email,
                        role=role,
                        department=department,
                        phone=phone,
                        active=active,
                        keycloak_id=user_response.get('id', '')
                    )
                    new_user.set_password(password)
                    
                    db.session.add(new_user)
                    db.session.commit()
                    
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
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('users_list'))
    
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        role = request.form.get('role')
        department = request.form.get('department')
        phone = request.form.get('phone')
        active = True if request.form.get('active') == 'on' else False
        
        try:
            if MOCK_MODE:
                # Check if email is being changed and already exists
                if email != user.email and User.query.filter_by(email=email).first():
                    flash('A user with this email already exists', 'danger')
                    return render_template('user_form.html', user=user.to_dict(), action='edit')
                
                # Update user in database
                user.first_name = first_name
                user.last_name = last_name
                user.email = email
                user.role = role
                user.department = department
                user.phone = phone
                user.active = active
                user.updated_at = datetime.utcnow()
                
                db.session.commit()
                
                flash('User updated successfully!', 'success')
                return redirect(url_for('users_list'))
            else:
                # Prepare data for User Service
                user_data = {
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': email,
                    'role': role,
                    'department': department,
                    'phone': phone,
                    'active': active
                }
                
                # Real user update through User Service
                headers = {'Authorization': f'Bearer {session["token"]}'}
                response = requests.put(
                    f"{USER_SERVICE_URL}/users/{user.keycloak_id}",
                    json=user_data,
                    headers=headers
                )
                
                if response.status_code == 200:
                    # Also update user in local database
                    user.first_name = first_name
                    user.last_name = last_name
                    user.email = email
                    user.role = role
                    user.department = department
                    user.phone = phone
                    user.active = active
                    user.updated_at = datetime.utcnow()
                    
                    db.session.commit()
                    
                    flash('User updated successfully!', 'success')
                    return redirect(url_for('users_list'))
                else:
                    error_message = response.json().get('detail', 'Failed to update user')
                    flash(error_message, 'danger')
        except Exception as e:
            flash(f'Error updating user: {str(e)}', 'danger')
            
    return render_template('user_form.html', user=user.to_dict(), action='edit')

@app.route('/users/delete/<user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('users_list'))
    
    try:
        if MOCK_MODE:
            # Delete user from database
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully!', 'success')
        else:
            # Real user deletion through User Service
            headers = {'Authorization': f'Bearer {session["token"]}'}
            
            if user.keycloak_id:
                # Delete user in Keycloak through User Service
                response = requests.delete(
                    f"{USER_SERVICE_URL}/users/{user.keycloak_id}",
                    headers=headers
                )
                
                if response.status_code == 204:
                    # Also delete user from local database
                    db.session.delete(user)
                    db.session.commit()
                    flash('User deleted successfully!', 'success')
                else:
                    error_message = response.json().get('detail', 'Failed to delete user from remote service')
                    flash(error_message, 'danger')
            else:
                # Just delete from local database if no Keycloak ID
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'danger')
        
    return redirect(url_for('users_list'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)