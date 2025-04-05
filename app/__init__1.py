# Plik: app/__init__.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate # USUNIĘTO: Flask-Migrate
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_babel import Babel # Importuj Babel
import os
import datetime # <<< DODANO IMPORT DATETIME >>>

app = Flask(__name__)

# Konfiguracja aplikacji
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'domyslny-slaby-klucz-do-rozwoju-zmien-to') # Użyj zmiennej środowiskowej lub zmień klucz
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zawody.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEST_MODE'] = False # Możesz używać tej flagi do warunkowej logiki

# Inicjalizacja rozszerzeń
db = SQLAlchemy(app)
# migrate = Migrate(app, db) # USUNIĘTO: Inicjalizacja Migrate
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Nazwa funkcji widoku logowania
login_manager.login_message_category = 'info' # Kategoria Bootstrap dla komunikatu flash
login_manager.login_message = "Zaloguj się, aby uzyskać dostęp do tej strony."
bcrypt = Bcrypt(app)

# === DODANO: Kontekst procesora do wstrzykiwania zmiennych globalnych do szablonów ===
@app.context_processor
def inject_now():
    """Udostępnia aktualny rok we wszystkich szablonach."""
    return {'current_year': datetime.datetime.now().year}
# === KONIEC DODAWANIA ===

# Ważne: Importy tras i modeli na końcu, aby uniknąć cyklicznych zależności
from app import routes, models