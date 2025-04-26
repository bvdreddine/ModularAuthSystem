import os
import sys
import traceback

try:
    print("=== Démarrage de l'application ModularAuthSystem ===")
    print(f"Python version: {sys.version}")
    print(f"Répertoire de travail: {os.getcwd()}")
    
    # Charger les variables d'environnement
    try:
        from dotenv import load_dotenv
        load_dotenv()
        print("✅ Variables d'environnement chargées")
    except Exception as e:
        print(f"❌ Erreur lors du chargement des variables d'environnement: {e}")
    
    # Importer Flask et SQLAlchemy
    try:
        from flask import Flask
        from flask_sqlalchemy import SQLAlchemy
        print("✅ Flask et SQLAlchemy importés avec succès")
    except Exception as e:
        print(f"❌ Erreur lors de l'importation de Flask ou SQLAlchemy: {e}")
        sys.exit(1)
    
    # Créer une application Flask de test
    try:
        app = Flask(__name__)
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        db = SQLAlchemy(app)
        print("✅ Application Flask créée avec succès")
    except Exception as e:
        print(f"❌ Erreur lors de la création de l'application Flask: {e}")
        sys.exit(1)
    
    # Tester la création de tables
    try:
        class TestModel(db.Model):
            id = db.Column(db.Integer, primary_key=True)
            name = db.Column(db.String(50))
        
        with app.app_context():
            db.create_all()
            print("✅ Base de données SQLite créée avec succès")
    except Exception as e:
        print(f"❌ Erreur lors de la création de la base de données: {e}")
        traceback.print_exc()
        sys.exit(1)
    
    # Importer et lancer l'application principale
    try:
        print("\n=== Lancement de l'application principale ===")
        import main
        print("✅ Application principale importée avec succès")
        
        # Lancer l'application
        if __name__ == "__main__":
            main.app.run(host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        print(f"❌ Erreur lors du lancement de l'application principale: {e}")
        traceback.print_exc()
        sys.exit(1)

except Exception as e:
    print(f"❌ Erreur générale: {e}")
    traceback.print_exc()
    sys.exit(1)
