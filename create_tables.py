# create_tables.py (Poprawiona kolejność)
import sys
import traceback
import os
from app import app, db, bcrypt
from app import models # Upewnij się, że wszystkie modele są zaimportowane

# --- Konfiguracja Danych Admina ---
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'TwojeBardzoSilneHaslo123!' # ZMIEŃ NA BEZPIECZNE HASŁO!
# Lub odczyt ze zmiennej środowiskowej
# ADMIN_PASSWORD = os.environ.get('INITIAL_ADMIN_PASSWORD')
# if not ADMIN_PASSWORD: sys.exit("!!! BŁĄD: Brak hasła admina w INITIAL_ADMIN_PASSWORD")
ADMIN_ROLE = 'admin'

def create_admin_user_if_not_exists():
    """Sprawdza i tworzy użytkownika admina, ZAKŁADAJĄC, że tabela 'user' już istnieje."""
    print(f"[Admin] Sprawdzanie czy użytkownik '{ADMIN_USERNAME}' istnieje...")
    try:
        existing_user = models.User.query.filter_by(username=ADMIN_USERNAME).first()
        if existing_user:
            print(f"[Admin] Użytkownik '{ADMIN_USERNAME}' już istnieje. Pomijanie tworzenia.")
            return True # Istnieje = sukces dla tego kroku

        print(f"[Admin] Tworzenie użytkownika '{ADMIN_USERNAME}' z rolą '{ADMIN_ROLE}'...")
        hashed_pw = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode('utf-8')
        admin_user = models.User(username=ADMIN_USERNAME, password=hashed_pw, role=ADMIN_ROLE)
        db.session.add(admin_user)
        # Commit będzie wykonany w funkcji głównej
        print(f"[Admin] Pomyślnie dodano admina '{ADMIN_USERNAME}' do sesji.")
        return True # Sukces dodania do sesji
    except Exception as e:
        print(f"[Admin] !!! BŁĄD podczas tworzenia/sprawdzania użytkownika admina: {e}")
        traceback.print_exc()
        db.session.rollback() # Wycofaj tylko tę operację, jeśli coś poszło nie tak
        return False # Błąd

def run_setup():
    """Główna funkcja skryptu: tworzy tabele, a następnie użytkownika admina."""
    print("--- Running Initial Setup Script ---")
    with app.app_context():
        try:
            # 1. Logowanie URI bazy danych
            masked_uri = "URI Error"; db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
            if db_uri: masked_uri = db_uri # Proste maskowanie można dodać później
            print(f"Attempting setup for database: {masked_uri[:40]}...")

            # 2. Tworzenie wszystkich tabel
            print("Attempting to execute db.create_all()...")
            db.create_all()
            print("--- db.create_all() executed (Tables created if they didn't exist) ---")

            # 3. Flush (opcjonalnie, ale może pomóc upewnić się, że CREATE TABLE dotarły do DB)
            # print("Flushing session to send CREATE TABLE statements...")
            # db.session.flush()
            # print("Session flushed.")

            # 4. Tworzenie użytkownika admina (TERAZ, gdy tabele na pewno istnieją)
            admin_creation_successful = create_admin_user_if_not_exists()

            # 5. Commit zmian (jeśli tworzenie admina się powiodło lub już istniał)
            if admin_creation_successful:
                try:
                    print("Committing session...")
                    db.session.commit()
                    print("--- Database commit successful ---")
                    print("--- Initial Setup Script Finished Successfully ---")
                    sys.exit(0) # Sukces
                except Exception as commit_e:
                    print(f"!!! ERROR during database commit: {commit_e}")
                    traceback.print_exc()
                    db.session.rollback()
                    sys.exit(1) # Błąd commita
            else:
                # Jeśli create_admin_user_if_not_exists zwróciło False
                print("!!! Admin user creation failed. Setup script failed.")
                # Rollback jest niepotrzebny, bo błąd był w create_admin... i tam był rollback
                sys.exit(1) # Błąd tworzenia admina

        except Exception as e:
            # Ogólny błąd podczas setupu (np. błąd połączenia przy create_all)
            print(f"!!! FATAL ERROR during database setup (before admin creation): {e}")
            traceback.print_exc()
            try: db.session.rollback()
            except: pass
            sys.exit(1)

if __name__ == '__main__':
    run_setup()
