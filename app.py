from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Création de l'application Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'azerty'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialisation de la base de données
db = SQLAlchemy(app)

# Configuration de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modèle utilisateur simplifié
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    role = db.Column(db.String(20))  # admin, teacher, student

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('username')  # Le champ s'appelle username dans le formulaire
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Identifiants incorrects. Veuillez réessayer.')
            
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.name, role=current_user.role)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Création des tables et des utilisateurs par défaut
def create_default_users():
    # Vérifier si des utilisateurs existent déjà
    if User.query.count() == 0:
        # Créer un administrateur
        admin = User(
            email='admin@example.com',
            name='Administrateur',
            role='admin',
            password=generate_password_hash('admin123', method='sha256')
        )
        
        # Créer un professeur
        teacher = User(
            email='teacher1@example.com',
            name='Professeur',
            role='teacher',
            password=generate_password_hash('teacher123', method='sha256')
        )
        
        # Créer un étudiant
        student = User(
            email='student1@example.com',
            name='Étudiant',
            role='student',
            password=generate_password_hash('student123', method='sha256')
        )
        
        # Ajouter les utilisateurs à la base de données
        db.session.add(admin)
        db.session.add(teacher)
        db.session.add(student)
        db.session.commit()
        
        print("Utilisateurs par défaut créés avec succès!")

# Initialisation de la base de données
with app.app_context():
    db.create_all()
    create_default_users()

# Lancement de l'application
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
