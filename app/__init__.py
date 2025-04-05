# Plik: app/__init__.py (Wersja BEZ Migrate, BEZ automatycznego db.create_all())

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
import os
from datetime import datetime
import logging # Importuj logging

# Inicjalizacja aplikacji Flask
app = Flask(__name__)

# --- Konfiguracja aplikacji ---
# WAŻNE: Ustaw bezpieczny klucz w zmiennej środowiskowej na Renderze!
# Odczytuje klucz ze zmiennej środowiskowej 'SECRET_KEY',
# lub używa klucza deweloperskiego, jeśli zmienna nie jest ustawiona LUB jesteś w trybie debug.
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    if os.environ.get('FLASK_DEBUG') == '1': # Sprawdź zmienną FLASK_DEBUG
        app.config['SECRET_KEY'] = 'tymczasowy-klucz-dev-tylko-do-testow'
        print("WARN: SECRET_KEY not set in environment. Using temporary development key because FLASK_DEBUG=1.")
    else:
        # W produkcji bez debugowania - rzuć błędem
        raise ValueError("FATAL ERROR: SECRET_KEY environment variable is not set!")
else:
    app.config['SECRET_KEY'] = SECRET_KEY


# --- Konfiguracja URI Bazy Danych (WYMAGANY PostgreSQL) ---
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') # Render ustawi tę zmienną

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
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Zalecane ustawienie

# --- Inicjalizacja rozszerzeń ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
# Usunięto Babel i Migrate

# --- Konfiguracja Flask-Login ---
login_manager.login_view = 'login' # Nazwa funkcji widoku (trasy) dla strony logowania
login_manager.login_message_category = 'info' # Kategoria Bootstrap dla wiadomości flash
login_manager.login_message = "Zaloguj się, aby uzyskać dostęp do tej strony."

# --- Kontekst procesor Jinja (tylko dla roku) ---
@app.context_processor
def inject_current_year():
    """Udostępnia aktualny rok we wszystkich szablonach jako zmienna 'current_year'."""
    return {'current_year': datetime.now().year}

# --- Importowanie Modułów Aplikacji ---
# WAŻNE: Modele muszą być zaimportowane, aby SQLAlchemy je znało
# Trasy importujemy na końcu
from app import models
from app import routes

# --- USUNIĘTO BLOK db.create_all() ---
# Tabele będą tworzone za pomocą dedykowanego skryptu create_tables.py

# --- Logowanie konfiguracji (z maskowaniem hasła) ---
try:
    masked_uri = "URI Error or Not Set"
    if app.config.get('SQLALCHEMY_DATABASE_URI'): # Użyj .get() dla bezpieczeństwa
        masked_uri = app.config['SQLALCHEMY_DATABASE_URI']
        if '@' in masked_uri:
            parts = masked_uri.split('@')
            creds_part = parts[0].split(':')
            # Proste maskowanie, zakładając format postgresql://user:password@host...
            if len(creds_part) > 2 and len(creds_part[2]) > 0:
                 masked_uri = f"{creds_part[0]}://{creds_part[1]}:***@{parts[1]}"
            elif len(creds_part) > 1:
                 masked_uri = f"{creds_part[0]}://***@{parts[1]}"
    # Loguj tylko początek URI dla bezpieczeństwa
    print(f"Flask app configured. Database URI starts with: {masked_uri[:min(len(masked_uri), 40)]}...")
except Exception as log_e:
    print(f"Error during logging configuration: {log_e}")
