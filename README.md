# ModularAuthSystem

Système d'authentification modulaire pour les établissements d'enseignement, permettant la gestion des utilisateurs (administrateurs, enseignants, étudiants), des cours et des inscriptions.

## Fonctionnalités

- Authentification et autorisation (login/logout)
- Gestion des utilisateurs (création, modification, suppression)
- Gestion des cours et des inscriptions
- Tableaux de bord spécifiques selon les rôles
- Architecture modulaire : mode monolithique ou microservices

## Technologies utilisées

- **Backend** : Python, Flask, SQLAlchemy
- **Base de données** : SQLite (développement) / PostgreSQL (production)
- **Microservices** (optionnels) : FastAPI, Keycloak, Cassandra
- **Frontend** : HTML/CSS/JavaScript, Bootstrap, Jinja2

## Guide d'installation et de déploiement

### Prérequis

- Git
- Docker et Docker Compose
- Accès à un terminal

### Installation avec Docker

1. **Cloner le dépôt**
   ```bash
   git clone https://github.com/votre-username/ModularAuthSystem.git
   cd ModularAuthSystem
   ```

2. **Configurer l'environnement**
   ```bash
   # Copier le fichier d'exemple
   cp .env.example .env
   
   # Modifier les variables selon vos besoins
   nano .env  # ou utilisez votre éditeur préféré
   ```

3. **Lancer l'application avec Docker Compose**

   Mode monolithique (par défaut) :
   ```bash
   # Lancer uniquement l'application principale
   docker-compose up app
   ```

   Mode microservices (optionnel) :
   ```bash
   # Lancer tous les services
   docker-compose up
   ```

4. **Accéder à l'application**
   - Ouvrez votre navigateur et accédez à `http://localhost:5000`

### Identifiants par défaut

| Rôle | Email | Mot de passe |
|------|-------|-------------|
| Administrateur | admin@example.com | admin123 |
| Enseignant | teacher1@example.com | teacher123 |
| Étudiant | student1@example.com | student123 |

## Structure du projet

```
ModularAuthSystem/
├── main.py                # Point d'entrée principal
├── models.py              # Modèles de données
├── templates/             # Templates HTML
├── auth_service/          # Microservice d'authentification
├── user_service/          # Microservice de gestion des utilisateurs
├── Dockerfile             # Configuration Docker pour l'app principale
├── Dockerfile.auth        # Configuration Docker pour le service d'auth
├── Dockerfile.user        # Configuration Docker pour le service utilisateur
├── docker-compose.yml     # Configuration Docker Compose
└── requirements.txt       # Dépendances Python
```

## Modes de fonctionnement

- **Mode monolithique** : Toutes les fonctionnalités sont intégrées dans une seule application Flask (MOCK_MODE = True)
- **Mode microservices** : L'application est divisée en services indépendants (MOCK_MODE = False)

## Personnalisation

- Pour utiliser PostgreSQL au lieu de SQLite, modifiez la variable `DATABASE_URL` dans le fichier `.env`
- Pour activer le mode microservices, modifiez `MOCK_MODE=false` dans le fichier `docker-compose.yml`

## Licence

Ce projet est sous licence MIT.
