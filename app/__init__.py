# Plik: app/__init__.py (Wersja WYMAGAJĄCA DATABASE_URL)

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
import os
from datetime import datetime
import logging

# Inicjalizacja aplikacji Flask
app = Flask(__name__)

# --- Konfiguracja aplikacji ---
# WAŻNE: Ustaw bezpieczny klucz w zmiennej środowiskowej!
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    # W środowisku deweloperskim MOŻNA ustawić domyślny klucz,
    # ale w produkcji MUSI być ustawiony w zmiennej środowiskowej.
    if app.debug: # Sprawdź, czy aplikacja jest w trybie debugowania
        app.config['SECRET_KEY'] = 'tymczasowy-klucz-dev-tylko-do-testow'
        print("WARN: SECRET_KEY not set in environment. Using temporary development key.")
    else:
        raise ValueError("FATAL ERROR: SECRET_KEY environment variable is not set!")

# --- Konfiguracja URI Bazy Danych (WYMAGANY PostgreSQL) ---
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

if not SQLALCHEMY_DATABASE_URI:
    # Jeśli DATABASE_URL nie jest ustawione - rzuć błędem
    raise ValueError("FATAL ERROR: DATABASE_URL environment variable is not set!")
elif SQLALCHEMY_DATABASE_URI.startswith('postgres://'):
     # Poprawka dla Render / Heroku
     SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://', 'postgresql://', 1)
     print("INFO: Using PostgreSQL database from DATABASE_URL environment variable.")
elif SQLALCHEMY_DATABASE_URI.startswith('postgresql://'):
     # Poprawny format już jest
     print("INFO: Using PostgreSQL database from DATABASE_URL environment variable.")
else:
     # Jeśli DATABASE_URL jest, ale nie jest to PostgreSQL
     raise ValueError(f"FATAL ERROR: DATABASE_URL does not point to a PostgreSQL database (found: {SQLALCHEMY_DATABASE_URI[:30]}...)")

app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Inicjalizacja rozszerzeń ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
# Usunięto Babel

# --- Konfiguracja Flask-Login ---
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = "Zaloguj się, aby uzyskać dostęp do tej strony."

# --- Kontekst procesor tylko dla roku ---
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

# --- Importowanie Modułów Aplikacji ---
# WAŻNE: Importuj modele PRZED potencjalnym db.create_all() lub migracjami
from app import models
from app import routes

# --- Tworzenie tabel bazy danych (BEZ MIGRACJI - opcjonalne) ---
# Jeśli nie używasz migracji, możesz zostawić ten blok.
# Jeśli używasz migracji, zakomentuj go lub usuń.
# with app.app_context():
#     try:
#         print("INFO: Checking and creating database tables if they don't exist...")
#         db.create_all()
#         print("INFO: Database tables checked/created.")
#     except Exception as e:
#         app.logger.error(f"ERROR: Could not create database tables: {e}", exc_info=True)
#         print(f"ERROR: Could not create database tables: {e}")

# --- Logowanie konfiguracji (z maskowaniem hasła) ---
try:
    masked_uri = "URI Not Set or Error"
    if app.config.get('SQLALCHEMY_DATABASE_URI'): # Użyj .get() dla bezpieczeństwa
        masked_uri = app.config['SQLALCHEMY_DATABASE_URI']
        if '@' in masked_uri:
            parts = masked_uri.split('@')
            creds_part = parts[0].split(':')
            if len(creds_part) > 2 and len(creds_part[2]) > 0:
                 masked_uri = f"{creds_part[0]}://{creds_part[1]}:***@{parts[1]}"
            elif len(creds_part) > 1:
                 masked_uri = f"{creds_part[0]}://***@{parts[1]}"
    print(f"Flask app configured. Database URI starts with: {masked_uri[:min(len(masked_uri), 40)]}...")
except Exception as log_e:
    print(f"Error during logging configuration: {log_e}")
