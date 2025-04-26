FROM python:3.11-slim

WORKDIR /app

# Copier les fichiers de dépendances
COPY requirements.txt .

# Installer les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY main.py .
COPY models.py .
COPY templates ./templates

# Créer un répertoire pour la base de données SQLite
RUN mkdir -p /app/instance

# Exposer le port
EXPOSE 5000

# Définir les variables d'environnement
ENV FLASK_APP=main.py
ENV PYTHONUNBUFFERED=1

# Commande par défaut
CMD ["python", "main.py"]
