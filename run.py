# run.py
# Główny punkt wejścia dla serwera Gunicorn

# Importuj instancję aplikacji 'app' z pakietu 'app' (czyli z app/__init__.py)
# Importuj również 'db' i 'models', aby były znane przy tworzeniu tabel przez create_all() w __init__.py
from app import app, db
from app import models

# Nie jest potrzebne wywoływanie app.run() tutaj.
# Gunicorn (zgodnie z Procfile: `web: gunicorn run:app`) zaimportuje
# zmienną 'app' z tego pliku i sam uruchomi serwer WSGI.

# Kod w bloku if __name__ == '__main__' jest opcjonalny,
# może służyć do uruchamiania serwera deweloperskiego Flaska lokalnie,
# ale nie będzie używany przez Gunicorna.
if __name__ == '__main__':
    print("INFO: Running application locally using Flask development server (NOT for production).")
    # Użyj host='0.0.0.0', aby serwer był dostępny z innych urządzeń w sieci lokalnej
    # Ustaw debug=True tylko podczas aktywnego rozwoju
    app.run(host='0.0.0.0', port=5000, debug=False)