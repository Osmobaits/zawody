# create_tables.py
import sys
from app import app, db
# WAŻNE: Zaimportuj WSZYSTKIE swoje modele, aby SQLAlchemy je "zobaczyło"
from app import models

print("--- Running Table Creation Script ---")
with app.app_context():
    try:
        print(f"Attempting to create tables for database: {app.config['SQLALCHEMY_DATABASE_URI'][:40]}...")
        db.create_all()
        print("--- Successfully executed db.create_all() ---")
        # Opcjonalnie: Możesz tu dodać tworzenie pierwszego admina, jeśli chcesz
        # print("Attempting to create initial admin...")
        # Tutaj kod z create_admin() z poprzednich odpowiedzi
        # ...
        sys.exit(0) # Zakończ sukcesem
    except Exception as e:
        print(f"!!! ERROR during db.create_all(): {e}")
        print("!!! Check database connection, user permissions, and model definitions.")
        traceback.print_exc() # Wydrukuj pełny traceback błędu
        sys.exit(1) # Zakończ z kodem błędu
