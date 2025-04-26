import os
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

print("=== Test de configuration ===")
print(f"Variables d'environnement chargées")
print(f"DATABASE_URL = {os.environ.get('DATABASE_URL')}")

try:
    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy
    
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///test.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    db = SQLAlchemy(app)
    
    class TestModel(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(50))
    
    with app.app_context():
        db.create_all()
        print("✅ Base de données SQLite créée avec succès!")
        print(f"Chemin de la base de données: {os.path.abspath('test.db')}")
    
except Exception as e:
    print(f"❌ Erreur: {e}")
    import traceback
    traceback.print_exc()
