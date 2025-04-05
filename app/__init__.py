# Plik: app/__init__.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
import os
from datetime import datetime
import logging # Dodaj import logging

# Inicjalizacja aplikacji Flask
app = Flask(__name__)

# --- Konfiguracja aplikacji ---
# WAŻNE: Ustaw bezpieczny klucz w zmiennej środowiskowej na Renderze!
# Odczytuje klucz ze zmiennej środowiskowej 'SECRET_KEY',
# lub używa klucza deweloperskiego, jeśli zmienna nie jest ustawiona.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'bardzo-tajny-domyslny-klucz-dev-zmien-mnie!')

# --- Konfiguracja URI Bazy Danych (PostgreSQL na Render / SQLite lokalnie) ---
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') # Render ustawi tę zmienną
if SQLALCHEMY_DATABASE_URI and SQLALCHEMY_DATABASE_URI.startswith('postgres://'):
     # Niektóre platformy (w tym Render) mogą używać 'postgres://'
     # SQLAlchemy oczekuje 'postgresql://'
     SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://', 'postgresql://', 1)
     print("INFO: Using PostgreSQL database from DATABASE_URL environment variable.")
else:
     # Fallback na lokalną bazę SQLite, jeśli DATABASE_URL nie jest ustawione
     # lub nie wskazuje na PostgreSQL (przydatne do lokalnego rozwoju)
     print("WARN: DATABASE_URL not set or not PostgreSQL. Falling back to local SQLite 'zawody.db'.")
     basedir = os.path.abspath(os.path.dirname(__file__))
     # Zakładamy, że baza 'zawody.db' znajduje się w głównym katalogu projektu (poziom wyżej niż folder 'app')
     db_path = os.path.join(basedir, '..', 'zawody.db')
     SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'

app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Zalecane ustawienie

# --- Inicjalizacja rozszerzeń ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
# Usunięto inicjalizację Babel i Migrate

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
# WAŻNE: Modele muszą być zaimportowane PRZED db.create_all()
from app import models # Zaimportuj WSZYSTKIE swoje modele
from app import routes # Zaimportuj trasy

# --- === Tworzenie tabel bazy danych (BEZ MIGRACJI) === ---
# Ten kod tworzy tabele zdefiniowane w models.py, jeśli jeszcze nie istnieją.
# Wykonuje się przy każdym starcie aplikacji (lub imporcie tego modułu).
with app.app_context():
    try:
        print("INFO: Checking and creating database tables if they don't exist...")
        db.create_all() # Tworzy tabele na podstawie zaimportowanych modeli
        print("INFO: Database tables checked/created.")
    except Exception as e:
        # Logowanie błędu, jeśli tworzenie tabel się nie powiedzie
        # (może to być błąd połączenia z bazą, błąd w definicji modelu itp.)
        app.logger.error(f"ERROR: Could not create database tables: {e}", exc_info=True)
        print(f"ERROR: Could not create database tables: {e}")
        # W środowisku produkcyjnym można rozważyć bardziej zaawansowaną obsługę
# --- === Koniec tworzenia tabel === ---

# --- Logowanie konfiguracji (z maskowaniem hasła) ---
try:
    masked_uri = "URI Error"
    if app.config['SQLALCHEMY_DATABASE_URI']:
        masked_uri = app.config['SQLALCHEMY_DATABASE_URI']
        if '@' in masked_uri:
            parts = masked_uri.split('@')
            creds_part = parts[0].split(':')
            # Proste maskowanie, zakładając format postgresql://user:password@host...
            if len(creds_part) > 2 and len(creds_part[2]) > 0: # user:password
                 masked_uri = f"{creds_part[0]}://{creds_part[1]}:***@{parts[1]}"
            elif len(creds_part) > 1: # user@ (bez hasła?)
                 masked_uri = f"{creds_part[0]}://***@{parts[1]}"
    # Loguj tylko początek URI dla bezpieczeństwa
    print(f"Flask app configured. Database URI starts with: {masked_uri[:min(len(masked_uri), 40)]}...")
except Exception as log_e:
    print(f"Error during logging configuration: {log_e}")