# create_tables.py
import sys
import traceback # Do drukowania pełnego błędu
import os # Do odczytu zmiennych środowiskowych (opcjonalnie dla hasła)
from app import app, db, bcrypt # Importuj app, db i bcrypt
# WAŻNE: Zaimportuj WSZYSTKIE swoje modele, aby SQLAlchemy je "zobaczyło"
# Jeśli modele są w app.models, to wystarczy:
from app import models
# Jeśli masz modele w innych plikach, zaimportuj je tutaj również.

# --- Konfiguracja Danych Admina ---
# Możesz ustawić nazwę użytkownika tutaj
ADMIN_USERNAME = 'Radek'

# HASŁO ADMINA - WYBIERZ JEDNĄ Z OPCJI:

# Opcja 1: Hasło wpisane na stałe (MNIEJ BEZPIECZNE, ale proste na start)
# PAMIĘTAJ, ABY ZMIENIĆ 'TwojeBardzoSilneHaslo123!' NA COŚ FAKTYCZNIE BEZPIECZNEGO!
ADMIN_PASSWORD = 'Zawody22'

# Opcja 2: Odczyt hasła ze zmiennej środowiskowej (BEZPIECZNIEJSZE)
# Wtedy musisz ustawić zmienną środowiskową INITIAL_ADMIN_PASSWORD w panelu Render
# ADMIN_PASSWORD = os.environ.get('INITIAL_ADMIN_PASSWORD')
# if not ADMIN_PASSWORD:
#     print("!!! BŁĄD KRYTYCZNY: Zmienna środowiskowa INITIAL_ADMIN_PASSWORD nie jest ustawiona! Nie można utworzyć admina.")
#     sys.exit(1) # Zakończ błędem

ADMIN_ROLE = 'admin' # Rola dla tworzonego użytkownika

def create_admin_user():
    """Tworzy użytkownika admina, jeśli jeszcze nie istnieje."""
    print(f"[Seed] Sprawdzanie czy użytkownik '{ADMIN_USERNAME}' istnieje...")
    # Używamy try-except na wypadek, gdyby nawet tabela User jeszcze nie istniała
    try:
        existing_user = models.User.query.filter_by(username=ADMIN_USERNAME).first()
    except Exception as e:
        print(f"[Seed] Błąd podczas sprawdzania użytkownika (może tabela nie istnieje?): {e}")
        existing_user = None # Zakładamy, że nie istnieje, jeśli tabela nie działa

    if existing_user:
        print(f"[Seed] Użytkownik '{ADMIN_USERNAME}' już istnieje. Pomijanie tworzenia.")
        return True # Traktujemy jako sukces, bo admin jest

    print(f"[Seed] Tworzenie użytkownika '{ADMIN_USERNAME}' z rolą '{ADMIN_ROLE}'...")
    try:
        hashed_pw = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode('utf-8')
        admin_user = models.User(username=ADMIN_USERNAME, password=hashed_pw, role=ADMIN_ROLE)
        db.session.add(admin_user)
        # Commit jest robiony zbiorczo po create_all i dodaniu admina
        print(f"[Seed] Pomyślnie przygotowano admina '{ADMIN_USERNAME}' do zapisu.")
        return True # Sukces przygotowania
    except Exception as e:
        print(f"[Seed] !!! BŁĄD podczas przygotowywania użytkownika admina: {e}")
        traceback.print_exc()
        return False # Błąd

def run_setup():
    """Główna funkcja skryptu: tworzy tabele i opcjonalnie admina."""
    print("--- Running Initial Setup Script ---")
    with app.app_context(): # Użyj kontekstu aplikacji Flask
        admin_prepared_ok = False
        try:
            # 1. Logowanie URI bazy danych (z maskowaniem)
            masked_uri = "URI Error"
            db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
            if db_uri:
                masked_uri = db_uri
                if '@' in masked_uri:
                    parts = masked_uri.split('@'); creds_part = parts[0].split(':')
                    if len(creds_part) > 2 and len(creds_part[2]) > 0: masked_uri = f"{creds_part[0]}://{creds_part[1]}:***@{parts[1]}"
                    elif len(creds_part) > 1: masked_uri = f"{creds_part[0]}://***@{parts[1]}"
            print(f"Attempting setup for database: {masked_uri[:min(len(masked_uri), 40)]}...")

            # 2. Tworzenie tabel
            print("Attempting to execute db.create_all()...")
            db.create_all()
            print("--- Successfully executed db.create_all() (Tables created if they didn't exist) ---")

            # 3. Tworzenie admina
            admin_prepared_ok = create_admin_user()

            # 4. Commit zmian (tworzenie tabel + dodanie admina)
            if admin_prepared_ok:
                print("Committing changes to the database...")
                db.session.commit()
                print("--- Database commit successful ---")
                print("--- Initial Setup Script Finished Successfully ---")
                sys.exit(0) # Zakończ sukcesem
            else:
                print("!!! Admin user preparation failed. Rolling back potential table creation.")
                db.session.rollback() # Wycofaj, jeśli admin się nie udał
                sys.exit(1) # Zakończ błędem

        except Exception as e:
            print(f"!!! ERROR during database setup: {e}")
            print("!!! Check database connection string (DATABASE_URL), user permissions, and model definitions.")
            traceback.print_exc()
            db.session.rollback() # Wycofaj zmiany w razie błędu
            sys.exit(1) # Zakończ z kodem błędu

if __name__ == '__main__':
    run_setup()
