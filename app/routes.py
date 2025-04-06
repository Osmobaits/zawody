from datetime import datetime
from flask import render_template, request, redirect, url_for, flash, session, make_response
from app import app, db, bcrypt
from app.models import Zawodnik, Zawody, WynikLosowania, UstawieniaZawodow, User, Wynik
from app.forms import ZawodnikForm, ZawodyForm, UstawieniaZawodowForm, RegistrationForm, LoginForm, WynikForm, FlaskForm # Dodano FlaskForm do pustego formularza
from flask_login import login_user, current_user, logout_user, login_required
import random
import itertools
from functools import wraps
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer, Paragraph
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from collections import Counter, defaultdict
from wtforms import FloatField, IntegerField # Dodano IntegerField
from wtforms.validators import Optional, NumberRange # Dodano NumberRange
import io
import traceback
from sqlalchemy import func # Potrzebne do sumowania
from sqlalchemy import desc
import re 
import os # Potrzebny do operacji na plikach/ścieżkach
from werkzeug.utils import secure_filename # Dobra praktyka, choć mniej krytyczna dla .txt


# =========================================
# DEFINICJA DEKORATORA ROLE_REQUIRED (NA POCZĄTKU)
# =========================================
def role_required(role):
    """
    Dekorator sprawdzający, czy zalogowany użytkownik ma wymaganą rolę.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Zaloguj się, aby uzyskać dostęp do tej strony.", 'info')
                return redirect(url_for('login', next=request.url))
            if current_user.role != role:
                flash(f'Nie masz wymaganych uprawnień ({role}), aby uzyskać dostęp do tej strony.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


import logging # Załóżmy, że masz skonfigurowany logger, np. app.logger

# Możesz użyć app.logger, jeśli definicja jest w pliku z aplikacją Flask
# W przeciwnym razie, skonfiguruj standardowy logger:
# logging.basicConfig(level=logging.DEBUG) # Na potrzeby testowania
# logger = logging.getLogger(__name__) # Używaj logger zamiast app.logger

# Zakładam użycie app.logger jak w poprzednich przykładach
from flask import current_app

def oblicz_punkty_sektorowe(wyniki_w_sektorze):
    """
    Oblicza punkty sektorowe TYLKO dla zawodników z wagą > 0.
    Zawodnicy z wagą <= 0 otrzymują 0 punktów za tę turę.

    Jest to odstępstwo od standardowych zasad GP.

    Args:
        wyniki_w_sektorze: Lista słowników, gdzie każdy słownik zawiera
                           co najmniej {'zawodnik_id': id, 'waga': laczna_waga}.
                           'waga' powinna być już sumą Waga(form) + BigFish(form).

    Returns:
        Słownik {zawodnik_id: punkty_sektorowe}.
    """
    # Użyj loggera aplikacji Flask, jeśli dostępny, inaczej standardowego
    logger = current_app.logger if current_app else logging.getLogger(__name__)

    logger.debug(f"    Calculating sector points (Zeros get 0 pts). Input: {wyniki_w_sektorze}")

    # 1. Podziel zawodników na tych z wagą > 0 i tych z wagą <= 0
    wyniki_z_waga = []
    ids_bez_wagi = set()
    # Sprawdź czy obiekt wejściowy jest iterowalny
    if not hasattr(wyniki_w_sektorze, '__iter__'):
        logger.error(f"      Input 'wyniki_w_sektorze' is not iterable: {wyniki_w_sektorze}")
        return {} # Zwróć pusty słownik w razie błędu

    for w in wyniki_w_sektorze:
        # Sprawdź czy element jest słownikiem i ma potrzebne klucze
        if not isinstance(w, dict) or 'zawodnik_id' not in w:
             logger.warning(f"      Skipping invalid entry in wyniki_w_sektorze: {w}")
             continue

        # Użyj .get z domyślną wartością 0 dla bezpieczeństwa
        waga_zawodnika = w.get('waga', 0)
        # Upewnij się, że waga jest liczbą (może być float lub int)
        if not isinstance(waga_zawodnika, (int, float)):
             try:
                 # Spróbuj skonwertować na float, traktuj niepowodzenie jak 0
                 waga_zawodnika = float(waga_zawodnika)
             except (ValueError, TypeError):
                 logger.warning(f"      Invalid weight type for competitor {w.get('zawodnik_id', 'N/A')}: {w.get('waga')}. Treating as 0.")
                 waga_zawodnika = 0

        if waga_zawodnika > 0:
            wyniki_z_waga.append(w)
        else:
            ids_bez_wagi.add(w['zawodnik_id'])

    punkty = {}

    # 2. Oblicz punkty tylko dla tych z wagą > 0
    if wyniki_z_waga:
        # Sortuj tylko tych z wagą > 0, malejąco wg wagi, potem ID dla stabilności
        posortowane = sorted(wyniki_z_waga, key=lambda x: (x.get('waga', 0), x.get('zawodnik_id', 0)), reverse=True)
        logger.debug(f"      Sorted results with weight > 0: {posortowane}")

        # N to teraz liczba zawodników z wagą > 0 w tym sektorze
        n_scoring = len(posortowane)

        i = 0
        aktualne_miejsce = 1 # Miejsca od 1 do n_scoring
        while i < n_scoring:
            # Gwarantowane > 0 i jest liczbą
            aktualna_waga = posortowane[i]['waga']

            # Znajdź grupę remisującą
            j = i
            while j < n_scoring and posortowane[j].get('waga') == aktualna_waga:
                j += 1

            liczba_remisujacych = j - i
            # Oblicz średnią z miejsc zajmowanych przez grupę remisującą
            suma_miejsc = sum(range(aktualne_miejsce, aktualne_miejsce + liczba_remisujacych))
            punkty_dla_grupy = suma_miejsc / liczba_remisujacych

            # Przypisz punkty tylko tym z wagą > 0
            for k in range(i, j):
                zawodnik_id = posortowane[k]['zawodnik_id']
                punkty[zawodnik_id] = punkty_dla_grupy
                logger.debug(f"        -> Competitor {zawodnik_id}: weight={aktualna_waga}, place={punkty_dla_grupy} (among {n_scoring} scoring)")

            # Przesuń miejsce startowe dla następnej grupy
            aktualne_miejsce += liczba_remisujacych
            # Przesuń indeks
            i = j
    else:
        logger.debug("      No competitors with weight > 0 in this sector.")
        # Wszyscy mają 0 wagę, więc wszyscy (którzy byli w `wyniki_w_sektorze`) dostają 0 punktów

    # 3. Przypisz 0 punktów tym, którzy mieli wagę <= 0
    for zid in ids_bez_wagi:
        # Sprawdzenie dla bezpieczeństwa, gdyby ID pojawiło się w obu grupach (nie powinno)
        if zid not in punkty:
            punkty[zid] = 0.0
            logger.debug(f"        -> Competitor {zid}: weight <= 0, gets 0.0 points")
        # Jeśli zawodnik z 0 wagą był też w `wyniki_z_waga` (nie powinno się zdarzyć),
        # jego punkty zostaną nadpisane przez 0.0 tutaj.

    logger.debug(f"      Returning points: {punkty}")
    return punkty

# Przykład użycia (poza aplikacją Flask):
if __name__ == '__main__':
    # Ustawienie loggera dla testów poza Flask
    import logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    test_sector_data_1 = [
        {'zawodnik_id': 1, 'waga': 1500},
        {'zawodnik_id': 2, 'waga': 1000},
        {'zawodnik_id': 3, 'waga': 1000},
        {'zawodnik_id': 4, 'waga': 0},
        {'zawodnik_id': 5, 'waga': 500},
        {'zawodnik_id': 6, 'waga': 0.0},
        {'zawodnik_id': 7}, # Test braku wagi
    ]
    logger.info("--- Test Case 1 ---")
    points1 = oblicz_punkty_sektorowe(test_sector_data_1)
    logger.info(f"Calculated points 1: {points1}")
    # Oczekiwane: {1: 1.0, 2: 2.5, 3: 2.5, 5: 4.0, 4: 0.0, 6: 0.0, 7: 0.0} (N=4)

    test_sector_data_2 = [
        {'zawodnik_id': 10, 'waga': 0},
        {'zawodnik_id': 11, 'waga': 0.0},
        {'zawodnik_id': 12},
    ]
    logger.info("\n--- Test Case 2 (Only zeros) ---")
    points2 = oblicz_punkty_sektorowe(test_sector_data_2)
    logger.info(f"Calculated points 2: {points2}")
    # Oczekiwane: {10: 0.0, 11: 0.0, 12: 0.0}

    test_sector_data_3 = [
        {'zawodnik_id': 20, 'waga': 200},
        {'zawodnik_id': 21, 'waga': 200},
    ]
    logger.info("\n--- Test Case 3 (Tie > 0) ---")
    points3 = oblicz_punkty_sektorowe(test_sector_data_3)
    logger.info(f"Calculated points 3: {points3}")
    # Oczekiwane: {20: 1.5, 21: 1.5} (N=2)

    test_sector_data_4 = []
    logger.info("\n--- Test Case 4 (Empty) ---")
    points4 = oblicz_punkty_sektorowe(test_sector_data_4)
    logger.info(f"Calculated points 4: {points4}")
    # Oczekiwane: {}
    
    
# =========================================
# DEFINICJE FUNKCJI POMOCNICZYCH (Losowanie)
# =========================================
def _losuj_sektory(wyniki, liczba_tur, ustawienia):
    """
    Przydziela sektory w ramach wylosowanych stref, BEZWZGLĘDNIE przestrzegając
    limitu stanowisk w sektorze.
    """
    if not ustawienia: return False # Zwróć błąd, jeśli brak ustawień
    liczba_stref = ustawienia.preferowana_liczba_stref
    liczba_sektorow_w_strefie = ustawienia.preferowana_liczba_sektorow
    limit_stanowisk_na_sektor = ustawienia.maks_liczba_stanowisk_w_sektorze

    strefa_do_sektorow = {}
    wszystkie_sektory = []
    for strefa_num in range(1, liczba_stref + 1):
        strefa_str = str(strefa_num)
        sektory_w_strefie = []
        for i in range(liczba_sektorow_w_strefie):
            litera = chr(65 + (strefa_num - 1) * liczba_sektorow_w_strefie + i)
            sektory_w_strefie.append(litera)
            wszystkie_sektory.append(litera)
        strefa_do_sektorow[strefa_str] = sektory_w_strefie

    print("=== _losuj_sektory (Wersja ze sztywnym limitem stanowisk) ===")
    print(f"Limit stanowisk na sektor: {limit_stanowisk_na_sektor}")
    print(f"Strefa do sektorów: {strefa_do_sektorow}")

    wszystko_ok_global = True

    for tura in range(1, liczba_tur + 1):
        if not wszystko_ok_global: break
        print(f"  Tura: {tura}")
        tura_strefa_attr = f'tura{tura}_strefa'
        tura_sektor_attr = f'tura{tura}_sektor'
        licznik_przydzialow_w_sektorach = defaultdict(int)

        for wynik in wyniki:
            strefa = getattr(wynik, tura_strefa_attr)
            sektor = getattr(wynik, tura_sektor_attr)
            if strefa and sektor:
                 licznik_przydzialow_w_sektorach[sektor] += 1

        print(f"    Początkowe przydziały w sektorach: {dict(licznik_przydzialow_w_sektorach)}")

        zawodnicy_do_przypisania = [w for w in wyniki if getattr(w, tura_strefa_attr) and not getattr(w, tura_sektor_attr)]
        random.shuffle(zawodnicy_do_przypisania)

        wszystko_ok_tura = True
        for wynik in zawodnicy_do_przypisania:
            strefa = getattr(wynik, tura_strefa_attr)
            zawodnik_id_aktualny = wynik.zawodnik_id if wynik.zawodnik else 'Puste'

            if strefa not in strefa_do_sektorow:
                print(f"    OSTRZEŻENIE: Zawodnik {zawodnik_id_aktualny} ma nieprawidłową strefę '{strefa}' w turze {tura}. Pomijanie.")
                continue
            dostepne_sektory_w_strefie = strefa_do_sektorow[strefa]

            print(f"    Zawodnik/Puste: {wynik.zawodnik.imie_nazwisko if wynik.zawodnik else 'Puste'} (ID: {zawodnik_id_aktualny}), Strefa: {strefa}, Dostępne sektory: {dostepne_sektory_w_strefie}")

            sektory_z_miejscami = [
                s for s in dostepne_sektory_w_strefie
                if licznik_przydzialow_w_sektorach[s] < limit_stanowisk_na_sektor
            ]

            if not sektory_z_miejscami:
                flash(f"BŁĄD KRYTYCZNY: Brak wolnych miejsc w sektorach strefy {strefa} dla zawodnika ID: {zawodnik_id_aktualny} w turze {tura}! "
                      f"Sprawdź, czy liczba zawodników w strefie ({len([w for w in wyniki if getattr(w, tura_strefa_attr) == strefa])}) "
                      f"nie przekracza sumy pojemności sektorów w tej strefie "
                      f"({len(dostepne_sektory_w_strefie)} sekt. * {limit_stanowisk_na_sektor} miejsc/sekt. = {len(dostepne_sektory_w_strefie) * limit_stanowisk_na_sektor} miejsc). "
                      f"Aktualne zapełnienie sektorów w strefie: "
                      f"{ {s: licznik_przydzialow_w_sektorach[s] for s in dostepne_sektory_w_strefie} }", "danger")
                print(f"      BŁĄD KRYTYCZNY: Brak wolnych sektorów w strefie {strefa} dla zawodnika ID: {zawodnik_id_aktualny} (Tura {tura}).")
                print(f"        Dostępne sektory strefy: {dostepne_sektory_w_strefie}")
                print(f"        Aktualne liczniki: { {s: licznik_przydzialow_w_sektorach[s] for s in dostepne_sektory_w_strefie} }")
                print(f"        Limit na sektor: {limit_stanowisk_na_sektor}")
                wszystko_ok_tura = False
                wszystko_ok_global = False
                break

            min_przydzialow_wsrod_dostepnych = min(licznik_przydzialow_w_sektorach[s] for s in sektory_z_miejscami)
            najlepsze_dostepne_sektory = [
                s for s in sektory_z_miejscami
                if licznik_przydzialow_w_sektorach[s] == min_przydzialow_wsrod_dostepnych
            ]

            wylosowany_sektor = random.choice(najlepsze_dostepne_sektory)
            setattr(wynik, tura_sektor_attr, wylosowany_sektor)
            licznik_przydzialow_w_sektorach[wylosowany_sektor] += 1

            print(f"      Wybrano sektor: {wylosowany_sektor} (Miał {min_przydzialow_wsrod_dostepnych} zaw., limit: {limit_stanowisk_na_sektor}). Najlepsze dostępne: {najlepsze_dostepne_sektory}. Aktualny licznik globalny: {dict(licznik_przydzialow_w_sektorach)}")

        if not wszystko_ok_tura:
             print(f"  Przerwano losowanie sektorów dla tury {tura} z powodu błędu krytycznego.")

    return wszystko_ok_global

def _losuj_stanowiska(wyniki, liczba_tur, ustawienia):
    """
    Przydziela stanowiska w ramach wylosowanych stref i sektorów.
    """
    if not ustawienia: return False
    liczba_stref = ustawienia.preferowana_liczba_stref
    liczba_sektorow_w_strefie = ustawienia.preferowana_liczba_sektorow
    maks_liczba_stanowisk_w_sektorze = ustawienia.maks_liczba_stanowisk_w_sektorze

    sektor_do_numerow = {}
    for strefa_num in range(1, liczba_stref + 1):
        for i in range(liczba_sektorow_w_strefie):
            sektor = chr(65 + (strefa_num - 1) * liczba_sektorow_w_strefie + i)
            start = ((strefa_num - 1) * liczba_sektorow_w_strefie + i) * maks_liczba_stanowisk_w_sektorze + 1
            stop = start + maks_liczba_stanowisk_w_sektorze
            sektor_do_numerow[sektor] = list(range(start, stop))

    print("=== _losuj_stanowiska ===")
    print(f"Sektor do numerów stanowisk: {sektor_do_numerow}")

    wszystko_ok_global = True
    for tura in range(1, liczba_tur + 1):
        if not wszystko_ok_global: break
        print(f"  Tura: {tura}")
        sektor_do_numerow_kopia = {k: v[:] for k, v in sektor_do_numerow.items()}
        tura_stanowisko_attr = f'tura{tura}_stanowisko'
        tura_sektor_attr = f'tura{tura}_sektor'

        zawodnicy_w_turze = [w for w in wyniki if getattr(w, tura_sektor_attr) and not getattr(w, tura_stanowisko_attr)]
        random.shuffle(zawodnicy_w_turze)

        wszystko_ok_tura = True
        for wynik in zawodnicy_w_turze:
            sektor = getattr(wynik, tura_sektor_attr)
            zawodnik_id_aktualny = wynik.zawodnik_id if wynik.zawodnik else 'Puste'

            if sektor and sektor in sektor_do_numerow_kopia:
                dostepne_stanowiska = sektor_do_numerow_kopia[sektor]
                print(f"    Zawodnik/Puste: {wynik.zawodnik.imie_nazwisko if wynik.zawodnik else 'Puste'} (ID: {zawodnik_id_aktualny}), Sektor: {sektor}, Dostępne stanowiska: {dostepne_stanowiska}")

                if dostepne_stanowiska:
                    wylosowane_stanowisko = random.choice(dostepne_stanowiska)
                    dostepne_stanowiska.remove(wylosowane_stanowisko)
                    setattr(wynik, tura_stanowisko_attr, wylosowane_stanowisko)
                    print(f"      Wylosowano stanowisko: {wylosowane_stanowisko}")
                else:
                    # Ten błąd NIE powinien wystąpić, jeśli _losuj_sektory działa poprawnie
                    # i nie przypisuje do sektora więcej zawodników niż limit_stanowisk_na_sektor
                    flash(f"BŁĄD KRYTYCZNY WEWNĘTRZNY: Brak dostępnych stanowisk w sektorze {sektor} dla tury {tura}! "
                          f"To wskazuje na problem w logice losowania sektorów lub niespójność danych.", "danger")
                    print(f"      BŁĄD KRYTYCZNY WEWNĘTRZNY: Brak dostępnych stanowisk w sektorze {sektor} (Tura {tura}) dla zawodnika ID: {zawodnik_id_aktualny}. Dostępne: {dostepne_stanowiska}")
                    wszystko_ok_tura = False
                    wszystko_ok_global = False
                    break # Przerwij losowanie dla tej tury
            elif not sektor:
                 print(f"    POMINIĘTO: Zawodnik ID: {zawodnik_id_aktualny} nie ma przypisanego sektora w turze {tura} przy losowaniu stanowisk.")
                 # To może się zdarzyć, jeśli _losuj_sektory nie przypisało sektora z powodu błędu
                 # Ustawiamy błąd globalny, bo losowanie nie jest kompletne
                 wszystko_ok_global = False
            else: # Sektor jest, ale nie ma go w mapie - błąd konfiguracji?
                 flash(f"BŁĄD KRYTYCZNY: Nieprawidłowy sektor '{sektor}' przypisany do zawodnika ID: {zawodnik_id_aktualny} w turze {tura}.", "danger")
                 print(f"    BŁĄD KRYTYCZNY: Nieprawidłowy sektor '{sektor}' dla ID: {zawodnik_id_aktualny} w turze {tura}.")
                 wszystko_ok_tura = False
                 wszystko_ok_global = False
                 break

        if not wszystko_ok_tura:
            print(f"  Przerwano losowanie stanowisk dla tury {tura} z powodu błędu.")

    return wszystko_ok_global

# =========================================
# DEFINICJE TRAS (Routes)
# =========================================

# Plik: app/routes.py

# === POCZĄTEK KODU DO WKLEJENIA ===

@app.route('/zawody/szczegoly/<int:zawody_id>') # Definiuje URL i pobiera ID
@login_required                                 # Wymaga zalogowania
def szczegoly_zawodow(zawody_id):               # Nazwa funkcji = nazwa endpointu
    """Wyświetla szczegółowe informacje o konkretnych zawodach."""
    print(f">>> Funkcja szczegoly_zawodow dla ID: {zawody_id}") # Log

    # Sprawdzenie poprawności ID (dodatkowe zabezpieczenie)
    if not isinstance(zawody_id, int) or zawody_id <= 0:
         flash("Nieprawidłowe ID zawodów.", "danger")
         return redirect(url_for('index'))

    # Pobierz zawody lub zwróć 404
    zawody = Zawody.query.get_or_404(zawody_id)

    # Pobierz powiązane dane
    try:
        zawodnicy = Zawodnik.query.filter_by(zawody_id=zawody_id).order_by(Zawodnik.is_puste_miejsce, Zawodnik.imie_nazwisko).all()
        wyniki_los = WynikLosowania.query.options(
            db.joinedload(WynikLosowania.zawodnik)
        ).filter_by(zawody_id=zawody_id).all()
        ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).first()
        # Można też pobrać wyniki wagowe, jeśli potrzebne
        # wyniki_wagowe = Wynik.query.filter_by(zawody_id=zawody_id).order_by(Wynik.tura, Wynik.waga.desc()).all()
    except Exception as e:
        print(f"!!! Błąd podczas pobierania danych dla zawodów {zawody_id}: {e}")
        flash("Wystąpił błąd podczas ładowania szczegółów zawodów.", "danger")
        return redirect(url_for('index'))

    # Sprawdź sesję przed renderowaniem szablonu (dobra praktyka)
    print(f"--- Renderuję szablon szczegoly_zawodow.html. Sesja: {session}") # LOG

    # Wyrenderuj szablon HTML, przekazując pobrane dane
    return render_template('szczegoly_zawodow.html',
                           zawody=zawody,
                           zawodnicy=zawodnicy,
                           wyniki=wyniki_los, # Przekaż wyniki losowania jako 'wyniki'
                           ustawienia=ustawienia
                           # wyniki_wagowe=wyniki_wagowe # Jeśli pobrano
                           )

# === KONIEC KODU DO WKLEJENIA ===

# ... reszta istniejącego kodu w app/routes.py ...

@app.route('/register', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Konto zostało utworzone!', 'success')
            return redirect(url_for('user_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Wystąpił błąd podczas tworzenia konta: {e}', 'danger')
    return render_template('register.html', title='Rejestracja', form=form)

# app/routes.py

# ... (importy) ...
from flask_login import login_required, current_user
# ...

@app.route('/wagowy')
@login_required
@role_required('wagowy') # Może być też lista: ['wagowy', 'admin'] jeśli admin też ma mieć dostęp
def wagowy_dashboard():
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    logger.info(f"User {current_user.username} (wagowy) accessing dashboard.")

    aktualne_zawody = None
    ustawienia = None
    liczba_tur = 0
    aktywne_tury_z_wynikami = set() # Zbiór numerów tur, które mają już jakieś wyniki

    if 'current_zawody_id' in session:
        zawody_id = session['current_zawody_id']
        try:
            aktualne_zawody = db.session.get(Zawody, zawody_id)
            if aktualne_zawody:
                ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).first()
                if ustawienia and ustawienia.liczba_tur:
                    liczba_tur = ustawienia.liczba_tur
                    # Sprawdź, które tury mają już wyniki
                    wyniki_q = db.session.query(Wynik.tura).filter_by(zawody_id=zawody_id).distinct().all()
                    aktywne_tury_z_wynikami = {r[0] for r in wyniki_q if r[0]}
            else:
                # ID w sesji jest nieprawidłowe
                session.pop('current_zawody_id', None)
                session.pop('current_zawody_nazwa', None)
                flash("Wybrane wcześniej zawody nie istnieją. Wybierz ponownie.", "warning")
        except Exception as e:
            logger.error(f"Error fetching current competition/settings for wagowy dashboard: {e}", exc_info=True)
            flash("Błąd podczas ładowania danych zawodów.", "danger")
            aktualne_zawody = None # Resetuj na wypadek błędu

    return render_template('wagowy_dashboard.html',
                           zawody=aktualne_zawody,
                           liczba_tur=liczba_tur,
                           aktywne_tury=aktywne_tury_z_wynikami)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # === DODAJ DEFINICJĘ LOGGERA ===
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    # === KONIEC DODAWANIA ===

    if current_user.is_authenticated:
        # Przekieruj na odpowiedni dashboard po zalogowaniu
        if current_user.role == 'wagowy':
             logger.debug(f"Authenticated user {current_user.username} (wagowy) redirected to wagowy_dashboard from login.")
             return redirect(url_for('wagowy_dashboard'))
        else: # Domyślnie dla admina lub innych ról
             logger.debug(f"Authenticated user {current_user.username} ({current_user.role}) redirected to index from login.")
             return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        # Użyj func.lower() dla porównania case-insensitive
        user = User.query.filter(func.lower(User.username) == func.lower(form.username.data)).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            logger.info(f"User '{user.username}' logged in successfully.")
            flash(f'Zalogowano pomyślnie jako {user.username}.', 'success')

            # Przekierowanie po logowaniu na podstawie roli
            if user.role == 'wagowy':
                 next_page = url_for('wagowy_dashboard')
                 logger.debug(f"Redirecting user {user.username} (wagowy) to {next_page}")
            else: # Domyślnie admin lub inne role
                 next_page = url_for('index')
                 logger.debug(f"Redirecting user {user.username} ({user.role}) to {next_page}")

            # Można dodać obsługę 'next' z request.args, ale na razie uproszczone
            return redirect(next_page)
        else:
            # Logowanie nieudane
            logger.warning(f"Failed login attempt for username: {form.username.data}")
            flash('Logowanie nieudane. Sprawdź nazwę użytkownika i hasło.', 'danger')

    # Dla GET lub nieudanego POST
    return render_template('login.html', title='Logowanie', form=form)

@app.route('/logout')
@login_required # Wylogować może się tylko zalogowany użytkownik
def logout():
    logger = current_app.logger if current_app else logging.getLogger(__name__) # Dodaj logger, jeśli go używasz
    username = current_user.username # Zapisz nazwę przed wylogowaniem
    logout_user() # Wyloguj użytkownika
    logger.info(f"User '{username}' logged out.")
    flash(f'Wylogowano pomyślnie użytkownika {username}.', 'success')

    # === ZMIANA TUTAJ ===
    # Zamiast przekierowywać do 'login'...
    # return redirect(url_for('login'))

    # ...przekieruj do 'index' (strona główna / landing page dla niezalogowanych)
    return redirect(url_for('index'))

@app.route("/")
@app.route("/index")
# Usunięto @login_required, bo chcemy, aby niezalogowani też widzieli stronę powitalną
def index():
    # Sprawdź, czy użytkownik jest zalogowany
    if current_user.is_authenticated:
        # Jeśli zalogowany, pokaż standardowy dashboard
        aktualne_zawody = None
        if 'current_zawody_id' in session:
            try:
                aktualne_zawody = db.session.get(Zawody, session['current_zawody_id']) # Nowsza składnia
                # lub dla starszych wersji: aktualne_zawody = Zawody.query.get(session['current_zawody_id'])
                if not aktualne_zawody:
                     session.pop('current_zawody_id', None)
                     session.pop('current_zawody_nazwa', None)
                     logger.warning(f"Cleared invalid current_zawody_id {session.get('current_zawody_id')} from session.")
            except Exception as e:
                 logger.error(f"Error fetching current competition (ID: {session.get('current_zawody_id')}) for index: {e}", exc_info=True)
                 aktualne_zawody = None
        # Renderuj standardowy szablon index.html dla zalogowanych
        return render_template('index.html', zawody=aktualne_zawody)
    else:
        # Jeśli niezalogowany, pokaż stronę powitalną z linkiem do logowania
        return render_template('landing_page.html')

@app.route("/admin")
@login_required
@role_required('admin')
def admin_panel():
    return render_template('admin.html')

@app.route('/users')
@login_required
@role_required('admin')
def user_list():
    try:
        users = User.query.order_by(User.username).all()
    except Exception as e:
        flash(f"Błąd podczas pobierania listy użytkowników: {e}", "danger")
        users = []
    return render_template('user_list.html', users=users)

# app/routes.py

# ... (importy: Flask, render_template, request, redirect, url_for, flash, session, db, ...)
# ... (importy: Zawodnik, Zawody, WynikLosowania, Wynik)
# ... (importy: ZawodnikForm)
# ... (import logger)
import os # Potrzebny do operacji na plikach/ścieżkach
from werkzeug.utils import secure_filename # Dobra praktyka, choć mniej krytyczna dla .txt

# === Funkcja pomocnicza do sprawdzania rozszerzeń ===
ALLOWED_EXTENSIONS = {'txt'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# === Dekorator role_required (zakładam, że jest zdefiniowany wcześniej w pliku) ===
# def role_required(role): ...

# === Trasa /zawodnicy ===
@app.route('/zawodnicy', methods=['GET', 'POST'])
@login_required
@role_required('admin') # Tylko admin może zarządzać zawodnikami
def zawodnicy():
    """
    Obsługuje wyświetlanie listy zawodników, dodawanie pojedynczego zawodnika
    oraz wczytywanie listy zawodników z pliku .txt (z czyszczeniem nazwisk).
    """
    # Użyj loggera aplikacji lub standardowego loggera
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    logger.debug(f"Accessing /zawodnicy route, method: {request.method}")

    # Sprawdzenie, czy zawody są wybrane w sesji
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz lub utwórz zawody!', 'warning')
        logger.warning("Access to /zawodnicy denied, no competition selected.")
        return redirect(url_for('zawody'))

    zawody_id = session['current_zawody_id']
    logger.debug(f"Current competition ID from session: {zawody_id}") # LOG 1

    # Sprawdzenie, czy wybrane zawody istnieją (na wypadek usunięcia w innej sesji)
    # Używamy db.session.get() (zalecane w SQLAlchemy 2.x) lub Zawody.query.get() dla starszych
    aktywne_zawody = db.session.get(Zawody, zawody_id)
    if not aktywne_zawody:
        session.pop('current_zawody_id', None)
        session.pop('current_zawody_nazwa', None)
        flash('Wybrane zawody już nie istnieją. Wybierz inne.', 'warning')
        logger.warning(f"Current competition ID {zawody_id} in session does not exist in DB.")
        return redirect(url_for('zawody'))

    # Formularz do dodawania pojedynczego zawodnika
    form_add_single = ZawodnikForm()

    # --- Obsługa POST ---
    if request.method == 'POST':

        # --- SPRAWDZENIE 1: Czy to UPLOAD PLIKU? ---
        if 'zawodnicy_file' in request.files:
            logger.info(f"Processing file upload for competition {zawody_id} by admin {current_user.username}")
            file = request.files['zawodnicy_file']

            # Sprawdzenie, czy plik został wybrany
            if file.filename == '':
                flash('Nie wybrano żadnego pliku do wczytania.', 'warning')
                return redirect(request.url) # Odśwież stronę

            # Sprawdzenie rozszerzenia i czy plik istnieje
            if file and allowed_file(file.filename):
                zawodnicy_z_pliku = []
                num_skipped_lines = 0 # Licznik pominiętych/pustych linii
                try:
                    # Odczytaj zawartość pliku, dekodując jako UTF-8
                    content = file.stream.read().decode('utf-8')
                    lines = content.splitlines() # Podziel na linie

                    for line_num, line in enumerate(lines, 1):
                        original_line = line.strip() # Usuń białe znaki z brzegów
                        if not original_line:
                            num_skipped_lines += 1
                            continue # Pomiń puste linie

                        # === CZYSZCZENIE NAZWISKA ===
                        name_no_digits = re.sub(r'\d+', '', original_line)
                        czyste_nazwisko = re.sub(r'[^A-Za-zĄąĆćĘęŁłŃńÓóŚśŹźŻż\s]+', '', name_no_digits).strip()
                        czyste_nazwisko = re.sub(r'\s{2,}', ' ', czyste_nazwisko).strip()
                        # === KONIEC CZYSZCZENIA ===

                        if czyste_nazwisko: # Jeśli coś zostało po czyszczeniu
                            zawodnicy_z_pliku.append(czyste_nazwisko)
                            if czyste_nazwisko != original_line:
                                logger.debug(f"Line {line_num}: Cleaned '{original_line}' to '{czyste_nazwisko}'")
                        else:
                            logger.warning(f"Line {line_num}: Skipped '{original_line}' - empty after cleaning.")
                            num_skipped_lines += 1

                    if not zawodnicy_z_pliku:
                         flash(f'Plik "{file.filename}" nie zawierał poprawnych nazwisk (po oczyszczeniu). Pominięto {num_skipped_lines} linii.', 'warning')
                         return redirect(request.url)

                    # === ZASTĘPOWANIE ZAWODNIKÓW W BAZIE (w transakcji) ===
                    logger.warning(f"Replacing ALL competitors and resetting draw/results for comp {zawody_id} from file {file.filename}.")
                    # Użycie with zapewnia automatyczny commit lub rollback
                    try:
                        with db.session.begin_nested(): # Lepsze zarządzanie transakcją
                            WynikLosowania.query.filter_by(zawody_id=zawody_id).delete()
                            Wynik.query.filter_by(zawody_id=zawody_id).delete()
                            Zawodnik.query.filter_by(zawody_id=zawody_id).delete()
                            logger.debug("Deleted existing draw, weight results, and competitors inside nested transaction.")

                            nowi_zawodnicy_obj = [
                                Zawodnik(imie_nazwisko=name, zawody_id=zawody_id, is_puste_miejsce=False)
                                for name in zawodnicy_z_pliku
                            ]
                            if nowi_zawodnicy_obj:
                                db.session.add_all(nowi_zawodnicy_obj)
                                logger.debug(f"Prepared {len(nowi_zawodnicy_obj)} new competitors for commit.")
                        # Jeśli blok with zakończył się bez błędu, nested commit jest gotowy
                        db.session.commit() # Główny commit
                        flash_msg = f'Pomyślnie wczytano i zastąpiono {len(zawodnicy_z_pliku)} zawodników z pliku "{file.filename}". Losowanie i wyniki zostały zresetowane.'
                        if num_skipped_lines > 0: flash_msg += f' Pominięto {num_skipped_lines} pustych lub nieprawidłowych linii.'
                        flash(flash_msg, 'success')
                        logger.info(f"Successfully loaded {len(zawodnicy_z_pliku)} competitors from file for comp {zawody_id}. Skipped lines: {num_skipped_lines}.")
                    except Exception as e: # Łapanie błędów wewnątrz transakcji
                        # Rollback jest automatyczny dzięki with db.session.begin_nested(), ale logujemy błąd
                        logger.error(f"Error during database operations for file upload (comp {zawody_id}): {e}", exc_info=True)
                        flash(f'Wystąpił błąd bazy danych podczas przetwarzania pliku: {e}', 'danger')
                        # Nie potrzebujemy tu db.session.rollback(), bo `with` to obsłużył

                except UnicodeDecodeError:
                     # Ten błąd występuje poza transakcją DB
                     logger.error(f"File encoding error for comp {zawody_id}, file {file.filename}. Make sure it's UTF-8.", exc_info=True)
                     flash('Błąd dekodowania pliku. Upewnij się, że plik jest zapisany w kodowaniu UTF-8.', 'danger')
                except Exception as e:
                     # Inne błędy poza transakcją DB
                     logger.error(f"Unexpected error processing uploaded file for comp {zawody_id}: {e}", exc_info=True)
                     flash(f'Wystąpił nieoczekiwany błąd podczas przetwarzania pliku: {e}', 'danger')

                return redirect(url_for('zawodnicy')) # Przekieruj ZAWSZE po próbie uploadu

            else:
                # Plik nie istnieje lub ma złe rozszerzenie
                flash('Niedozwolony typ pliku. Akceptowane są tylko pliki .txt', 'warning')
                return redirect(request.url)

        # --- SPRAWDZENIE 2: Czy to formularz dodawania POJEDYNCZEGO zawodnika? ---
        elif form_add_single.validate_on_submit():
            logger.info(f"Processing single competitor add for competition {zawody_id} by admin {current_user.username}")
            nowy_zawodnik = Zawodnik(imie_nazwisko=form_add_single.imie_nazwisko.data.strip(), zawody_id=zawody_id)
            db.session.add(nowy_zawodnik)
            try:
                # Dodanie NOWEGO zawodnika NADAL resetuje losowanie i wyniki
                logger.warning(f"Resetting draw and weight results due to adding single competitor '{nowy_zawodnik.imie_nazwisko}' to competition {zawody_id}.")
                WynikLosowania.query.filter_by(zawody_id=zawody_id).delete()
                Wynik.query.filter_by(zawody_id=zawody_id).delete()
                db.session.commit()
                flash(f'Zawodnik "{nowy_zawodnik.imie_nazwisko}" dodany! UWAGA: Wyniki losowania i wyniki wagowe zostały zresetowane dla wszystkich.', 'warning')
            except SQLAlchemyError as db_err: # Lepsze łapanie błędów DB
                db.session.rollback()
                logger.error(f"Database error adding single competitor '{form_add_single.imie_nazwisko.data}' to comp {zawody_id}: {db_err}", exc_info=True)
                flash(f'Błąd bazy danych podczas dodawania zawodnika: {db_err}', 'danger')
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error adding single competitor '{form_add_single.imie_nazwisko.data}' to comp {zawody_id}: {e}", exc_info=True)
                flash(f'Błąd podczas dodawania zawodnika: {e}', 'danger')
            return redirect(url_for('zawodnicy')) # Redirect po dodaniu

        # Jeśli POST, ale nie upload i nie poprawny formularz dodawania (np. błąd walidacji form_add_single)
        elif request.method == 'POST':
             logger.warning(f"POST request to /zawodnicy was not a valid file upload or single add form submission. Single form errors: {form_add_single.errors}")
             # Nie przekierowuj, pozwól render_template poniżej wyświetlić błędy formularza form_add_single


    # --- Obsługa GET ---
    # Pobierz listę zawodników DO WYŚWIETLENIA (teraz powinna być aktualna po redirect)
    logger.debug(f"Handling GET request for /zawodnicy, competition ID: {zawody_id}") # LOG 2
    zawodnicy_lista = []
    try:
        # --- === KLUCZOWE ZAPYTANIE === ---
        zawodnicy_lista = Zawodnik.query.filter_by(zawody_id=zawody_id)\
            .order_by(Zawodnik.is_puste_miejsce.asc(), Zawodnik.imie_nazwisko.asc())\
            .all()
        # --- === KONIEC ZAPYTANIA === ---

        # --- === Logi debugowe === ---
        logger.info(f"Fetched {len(zawodnicy_lista)} competitors from DB for competition ID: {zawody_id}.") # LOG 3 (Użyj INFO dla pewności)
        if zawodnicy_lista:
             # Poprawiony log, używa pojedynczych cudzysłowów wewnątrz f-stringa
             competitor_info = [f"{z.id}:{z.imie_nazwisko or 'Puste'}" for z in zawodnicy_lista[:5]]
             logger.debug(f"First few competitors fetched: {competitor_info}") # LOG 4
        else:
            logger.warning(f"No competitors found in DB for competition ID: {zawody_id}") # LOG 5
        # --- === Koniec logów === ---

    except KeyError: # Ten błąd jest już obsłużony na początku funkcji GET
         # Można usunąć ten blok, jeśli jest już obsłużony wyżej
         logger.error("Error fetching competitor list: 'current_zawody_id' not found in session during GET.")
         flash("Błąd sesji: Nie wybrano aktywnych zawodów.", "danger")
         return redirect(url_for('zawody'))
    except Exception as e:
         logger.error(f"Error fetching competitor list for comp {zawody_id} (GET): {e}", exc_info=True)
         flash(f"Błąd podczas pobierania listy zawodników: {e}", "danger")
         zawodnicy_lista = [] # Zwróć pustą listę w razie błędu

    # Przekaż form_add_single (może zawierać błędy z POST) i pobraną listę zawodników
    logger.debug(f"Rendering zawodnicy.html with {len(zawodnicy_lista)} competitors.") # LOG 6
    return render_template('zawodnicy.html', form=form_add_single, zawodnicy=zawodnicy_lista)

@app.route('/edytuj_zawodnikow', methods=['POST'])
@login_required
@role_required('admin')
def edytuj_zawodnikow():
    # === DODAJ DEFINICJĘ LOGGERA ===
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    # === KONIEC DODAWANIA ===

    logger.info(f">>> Processing competitor edits by admin {current_user.username}")
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    zawody_id = session['current_zawody_id']
    # Użyj with_for_update, jeśli oczekujesz dużego ruchu, aby zablokować wiersze - opcjonalne
    # zawodnicy_do_edycji = Zawodnik.query.with_for_update().filter_by(zawody_id=zawody_id).all()
    zawodnicy_do_edycji = Zawodnik.query.filter_by(zawody_id=zawody_id).all()

    zmodyfikowano = False
    zawodnicy_do_wyczyszczenia_wynikow = []

    for zawodnik in zawodnicy_do_edycji:
        pole_name = f'imie_nazwisko_{zawodnik.id}'
        nowe_imie_nazwisko_str = request.form.get(pole_name)

        if nowe_imie_nazwisko_str is not None:
            nowe_imie_nazwisko = nowe_imie_nazwisko_str.strip()
            oryginalne_imie_nazwisko = zawodnik.imie_nazwisko
            oryginalny_status_pusty = zawodnik.is_puste_miejsce

            if nowe_imie_nazwisko == "": # Cel: Zmiana na Puste Miejsce
                if not oryginalny_status_pusty:
                    logger.debug(f"Changing competitor {zawodnik.id} ('{oryginalne_imie_nazwisko}') to an empty slot.")
                    zawodnicy_do_wyczyszczenia_wynikow.append(zawodnik.id)
                    zawodnik.imie_nazwisko = None
                    zawodnik.is_puste_miejsce = True
                    zmodyfikowano = True
            else: # Cel: Zmiana na Rzeczywistego lub zmiana nazwiska
                if oryginalne_imie_nazwisko != nowe_imie_nazwisko or oryginalny_status_pusty:
                    if oryginalny_status_pusty:
                        logger.debug(f"Changing empty slot {zawodnik.id} to competitor '{nowe_imie_nazwisko}'.")
                    else:
                        logger.debug(f"Changing name for competitor {zawodnik.id} from '{oryginalne_imie_nazwisko}' to '{nowe_imie_nazwisko}'.")
                    zawodnik.imie_nazwisko = nowe_imie_nazwisko
                    zawodnik.is_puste_miejsce = False
                    zmodyfikowano = True

    if zmodyfikowano:
        try:
            if zawodnicy_do_wyczyszczenia_wynikow:
                 logger.warning(f"Clearing weight results for competitors turned into empty slots: {zawodnicy_do_wyczyszczenia_wynikow}")
                 Wynik.query.filter(
                     Wynik.zawody_id == zawody_id,
                     Wynik.zawodnik_id.in_(zawodnicy_do_wyczyszczenia_wynikow)
                 ).delete(synchronize_session='fetch') # Zmieniono na 'fetch' dla potencjalnie lepszej wydajności

            db.session.commit()
            logger.info(f"Admin {current_user.username} updated competitor list for comp {zawody_id}. Draw NOT reset. Cleared results only for {len(zawodnicy_do_wyczyszczenia_wynikow)} competitors changed to empty.")

            if zawodnicy_do_wyczyszczenia_wynikow:
                 flash('Zaktualizowano dane zawodników! Wyniki wagowe zawodników zmienionych na "Puste miejsce" zostały usunięte. Losowanie i wyniki pozostałych zawodników NIE zostały zresetowane.', 'success')
            else:
                 flash('Zaktualizowano dane zawodników! Losowanie i wyniki wagowe NIE zostały zresetowane.', 'success')

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error saving competitor edits for comp {zawody_id}: {e}", exc_info=True)
            flash(f'Błąd podczas zapisywania zmian: {e}', 'danger')
    else:
        flash('Nie wprowadzono żadnych zmian w danych zawodników.', 'info')

    return redirect(url_for('zawodnicy'))

# app/routes.py

# ... (importy jak wyżej) ...
from app.models import Zawodnik, WynikLosowania, Wynik # Importuj WynikLosowania i Wynik

@app.route('/zawodnicy/usun/<int:id>', methods=['POST'])
@login_required
@role_required('admin')
def usun_zawodnika(id):
    # === DODAJ DEFINICJĘ LOGGERA ===
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    # === KONIEC DODAWANIA ===

    logger.info(f"Admin {current_user.username} attempting to delete competitor ID {id}")
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    # Użyj get_or_404 dla zwięzłości
    zawodnik = db.session.get(Zawodnik, id) # Nowsza składnia SQLAlchemy 2.x
    if not zawodnik:
         flash(f"Nie znaleziono zawodnika o ID {id}.", 'error')
         return redirect(url_for('zawodnicy'))
    # lub dla starszych wersji SQLAlchemy:
    # zawodnik = Zawodnik.query.get_or_404(id)


    if zawodnik.zawody_id != session['current_zawody_id']:
        flash("Nie można usunąć zawodnika z innych zawodów.", 'error')
        logger.warning(f"Admin {current_user.username} tried to delete competitor {id} from wrong competition ({zawodnik.zawody_id} instead of {session['current_zawody_id']})")
        return redirect(url_for('zawodnicy'))

    imie_nazwisko_us = zawodnik.imie_nazwisko or "Puste miejsce"
    zawody_id = session['current_zawody_id']
    zawodnik_id_do_us = zawodnik.id

    try:
        # Usuwamy tylko wpisy dla tego konkretnego zawodnika
        logger.debug(f"Deleting specific draw results for competitor ID {zawodnik_id_do_us} in competition {zawody_id}")
        WynikLosowania.query.filter_by(zawody_id=zawody_id, zawodnik_id=zawodnik_id_do_us).delete(synchronize_session='fetch')

        logger.debug(f"Deleting specific weight results for competitor ID {zawodnik_id_do_us} in competition {zawody_id}")
        Wynik.query.filter_by(zawody_id=zawody_id, zawodnik_id=zawodnik_id_do_us).delete(synchronize_session='fetch')

        # Usuwamy samego zawodnika
        logger.debug(f"Deleting competitor object ID {zawodnik_id_do_us}")
        db.session.delete(zawodnik)

        db.session.commit()
        logger.info(f"Admin {current_user.username} deleted competitor ID {zawodnik_id_do_us} ('{imie_nazwisko_us}') from competition {zawody_id}. Specific draw/weight results deleted. Full draw NOT reset.")
        flash(f'Zawodnik "{imie_nazwisko_us}" usunięty! Powiązane z nim wyniki losowania i wagowe zostały usunięte. Losowanie dla pozostałych NIE zostało zresetowane.', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting competitor ID {zawodnik_id_do_us} from comp {zawody_id}: {e}", exc_info=True)
        flash(f'Błąd podczas usuwania zawodnika: {e}', 'danger')

    return redirect(url_for('zawodnicy'))

# ... (inne trasy) ...

@app.route('/losowanie', methods=['GET'])
@login_required
@role_required('admin')
def losowanie():
  if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))
  return render_template('losowanie.html')

# === Trasa /losuj_sekwencje (TWOJA ISTNIEJĄCA TRASA Z PONAWIANIEM) ===
@app.route('/losuj_sekwencje', methods=['POST'])
@login_required
@role_required('admin')
def losuj_sekwencje(): # Używamy Twojej nazwy funkcji
    """
    Losuje sekwencje stref dla wszystkich zawodników (wypełniając pustymi miejscami).
    Automatycznie ponawia próbę losowania (do MAX_PROB razy), jeśli pierwsza się nie powiedzie.
    Resetuje poprzednie losowanie i wyniki wagowe.
    """
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    logger.info(f">>> Starting Zone Sequence Draw (with retries) by admin {current_user.username}")
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    zawody_id = session['current_zawody_id']
    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).first()
    if not ustawienia:
        flash("Najpierw ustaw parametry zawodów!", "error")
        return redirect(url_for("ustawienia"))

    # --- Krok 0: Przygotowanie zawodników i czyszczenie starych danych ---
    try:
        # Pobierz parametry, sprawdź ich poprawność
        liczba_stref = ustawienia.preferowana_liczba_stref
        liczba_sektorow = ustawienia.preferowana_liczba_sektorow # Potrzebne do pojemności
        maks_stanowisk = ustawienia.maks_liczba_stanowisk_w_sektorze # Potrzebne do pojemności
        liczba_tur = ustawienia.liczba_tur
        # === POPRAWIONA WALIDACJA USTAWIEŃ ===
        if not all(isinstance(val, int) and val > 0 for val in [liczba_stref, liczba_sektorow, maks_stanowisk, liczba_tur]):
             raise ValueError("Nieprawidłowe ustawienia (wartości muszą być dodatnimi liczbami całkowitymi).")
        maks_miejsc = liczba_stref * liczba_sektorow * maks_stanowisk
        logger.debug(f"Calculated capacity: {maks_miejsc} spots.")

        # Sprawdź zgodność liczby tur i stref
        if liczba_tur > liczba_stref:
            flash(f"Liczba tur ({liczba_tur}) nie może być większa niż liczba stref ({liczba_stref})!", "error")
            logger.warning(f"Draw aborted: Rounds ({liczba_tur}) > Zones ({liczba_stref}).")
            return redirect(url_for('ustawienia'))

        # Pobierz liczbę rzeczywistych zawodników
        aktualni_zawodnicy_count = Zawodnik.query.filter_by(zawody_id=zawody_id, is_puste_miejsce=False).count()
        liczba_pustych_do_dodania = maks_miejsc - aktualni_zawodnicy_count
        logger.debug(f"Real competitors: {aktualni_zawodnicy_count}, Empty slots to add: {liczba_pustych_do_dodania}")

        if liczba_pustych_do_dodania < 0:
            flash(f"Liczba zapisanych zawodników ({aktualni_zawodnicy_count}) przekracza maksymalną pojemność ({maks_miejsc})!", "danger")
            logger.error(f"Draw aborted: Competitors ({aktualni_zawodnicy_count}) > Capacity ({maks_miejsc}).")
            return redirect(url_for('zawodnicy'))

        # Przygotuj listę w transakcji
        # Użycie with zapewnia automatyczny commit lub rollback
        with db.session.begin_nested():
            logger.warning(f"Sequence Draw: Clearing old draw/weight data and empty slots for comp {zawody_id}")
            # Usuń stare dane losowania i wyników
            WynikLosowania.query.filter_by(zawody_id=zawody_id).delete(synchronize_session=False) # Lepsze dla wydajności
            Wynik.query.filter_by(zawody_id=zawody_id).delete(synchronize_session=False)
            # Usuń tylko PUSTE miejsca
            Zawodnik.query.filter_by(zawody_id=zawody_id, is_puste_miejsce=True).delete(synchronize_session=False)
            # Dodaj nowe puste miejsca, jeśli potrzeba
            if liczba_pustych_do_dodania > 0:
                logger.info(f"Adding {liczba_pustych_do_dodania} empty slots.")
                db.session.add_all([Zawodnik(zawody_id=zawody_id, is_puste_miejsce=True) for _ in range(liczba_pustych_do_dodania)])
        db.session.commit() # Zatwierdź przygotowanie listy
        logger.debug("Competitor list preparation committed.")

    except ValueError as ve:
         flash(f"Błąd w ustawieniach: {ve}", "danger"); return redirect(url_for('ustawienia'))
    except SQLAlchemyError as db_err: # Łap błędy DB przy czyszczeniu/dodawaniu
        db.session.rollback(); logger.error(f"Sequence Draw: DB Error preparing competitors: {db_err}", exc_info=True); flash(f"Błąd bazy danych podczas przygotowania listy: {db_err}", "danger"); return redirect(url_for('zawodnicy'))
    except Exception as e: # Inne błędy
        db.session.rollback(); logger.error(f"Sequence Draw: Error preparing competitors: {e}", exc_info=True); flash(f"Błąd przygotowania listy: {e}", "danger"); return redirect(url_for('zawodnicy'))

    # Pobierz pełną listę zawodników po przygotowaniu
    try:
        zawodnicy_do_losowania = Zawodnik.query.filter_by(zawody_id=zawody_id).all()
        liczba_zawodnikow_do_los = len(zawodnicy_do_losowania)
    except Exception as e:
        logger.error(f"Sequence Draw: Error fetching prepared competitors: {e}", exc_info=True); flash(f"Błąd pobierania listy do losowania: {e}", "danger"); return redirect(url_for('zawodnicy'))

    # Dodatkowe sprawdzenia po przygotowaniu
    if liczba_zawodnikow_do_los != maks_miejsc:
         flash(f"Błąd wewnętrzny: Niezgodność liczby zawodników ({liczba_zawodnikow_do_los}) z pojemnością ({maks_miejsc}) po przygotowaniu listy.", "danger"); return redirect(url_for('zawodnicy'))
    if not zawodnicy_do_losowania:
         flash("Brak zawodników do losowania.", "warning"); return redirect(url_for('zawodnicy'))

    # === Losowanie Sekwencji Stref z PĘTLĄ PONAWIANIA ===
    logger.info("Sequence Draw: Drawing Zone Sequences (with retries)...")
    MAX_PROB_LOSOWANIA_STREF = 20 # Zwiększono liczbę prób
    macierz_losowania = None # Wynikowa macierz
    sukces_losowania_stref = False
    last_error_flash = None # Zapisz ostatni błąd flash z pętli

    for proba in range(MAX_PROB_LOSOWANIA_STREF):
        logger.debug(f"Attempting zone sequence draw: Trial {proba + 1}/{MAX_PROB_LOSOWANIA_STREF}")
        # Tworzymy tymczasową macierz dla tej próby
        macierz_temp = [[None] * liczba_tur for _ in range(liczba_zawodnikow_do_los)]
        ok_proba = True # Flaga sukcesu dla tej próby
        last_error_flash = None # Resetuj błąd dla tej próby

        try:
            # --- Logika losowania stref (jak w /losuj_sekwencje) ---
            strefy = [str(i) for i in range(1, liczba_stref + 1)]
            idl = liczba_zawodnikow_do_los // liczba_stref
            resz = liczba_zawodnikow_do_los % liczba_stref
            SCISLE_LIMITY_STREF = {s: idl + (1 if int(s) <= resz else 0) for s in strefy}
            indeks_na_id = {i: z.id for i, z in enumerate(zawodnicy_do_losowania)} # Mapa indeks -> ID

            for t in range(liczba_tur): # Pętla po turach
                if not ok_proba: break # Jeśli coś poszło nie tak w tej próbie, przerwij tury
                liczniki_stref_w_turze = defaultdict(int)
                # Przygotuj opcje dla zawodników
                opcje_dla_zawodnika = {}
                for idx in range(liczba_zawodnikow_do_los):
                    poprzednie = [macierz_temp[idx][pt] for pt in range(t) if macierz_temp[idx][pt] is not None]
                    opcje_dla_zawodnika[idx] = {'nieodwiedzone': [s for s in strefy if s not in poprzednie]}
                    opcje_dla_zawodnika[idx]['liczba_opcji'] = len(opcje_dla_zawodnika[idx]['nieodwiedzone'])
                # Posortuj wg liczby opcji (rosnąco)
                indeksy_posortowane = sorted(range(liczba_zawodnikow_do_los), key=lambda idx: opcje_dla_zawodnika[idx]['liczba_opcji'])

                # Przypisz strefy w posortowanej kolejności
                for i in indeksy_posortowane: # Pętla po zawodnikach (posortowanych)
                    strefy_nieodwiedzone_zaw = opcje_dla_zawodnika[i]['nieodwiedzone']
                    # Znajdź możliwe strefy (nieodwiedzone i z miejscem wg limitu tury)
                    strefy_mozliwe = [s for s in strefy_nieodwiedzone_zaw if liczniki_stref_w_turze[s] < SCISLE_LIMITY_STREF.get(s, 0)]

                    if not strefy_mozliwe:
                        # Błąd krytyczny - nie można przypisać strefy
                        zaw_id_err = indeks_na_id.get(i, f'Index {i}')
                        last_error_flash = (f"Próba {proba + 1} nieudana: Brak możliwej strefy dla ID: {zaw_id_err} w Turze {t + 1}. "
                                            f"Nieodwiedzone: {strefy_nieodwiedzone_zaw}, Liczniki: {dict(liczniki_stref_w_turze)}, Limity: {SCISLE_LIMITY_STREF}")
                        logger.warning(last_error_flash + " Retrying...")
                        ok_proba = False; break # Przerwij pętlę po zawodnikach DLA TEJ TURY i tej próby

                    # Wybierz najlepszą z możliwych (najmniej zapełnioną)
                    min_licznik = min(liczniki_stref_w_turze[s] for s in strefy_mozliwe)
                    najlepsze = [s for s in strefy_mozliwe if liczniki_stref_w_turze[s] == min_licznik]
                    # Wylosuj jedną z najlepszych
                    wylosowana_strefa = random.choice(najlepsze)
                    macierz_temp[i][t] = wylosowana_strefa
                    liczniki_stref_w_turze[wylosowana_strefa] += 1
                # Koniec pętli po zawodnikach dla tury 't'
                if not ok_proba: break # Jeśli błąd w pętli po zawodnikach, przerwij też pętlę po turach
            # Koniec pętli po turach dla próby 'proba'

            # Sprawdź kompletność macierzy po zakończeniu wszystkich tur DLA TEJ PRÓBY
            if ok_proba: # Jeśli nie było błędu "braku możliwej strefy"
                if all(all(row) for row in macierz_temp): # Sprawdź, czy wszystkie komórki są wypełnione
                    logger.info(f"Zone sequence draw successful on trial {proba + 1}.")
                    macierz_losowania = macierz_temp # Przypisz udaną macierz
                    sukces_losowania_stref = True
                    break # SUKCES! Wyjdź z pętli prób
                else: # Pętla po turach się zakończyła, ale macierz niekompletna
                     last_error_flash = f"Próba {proba + 1} nieudana: Wygenerowana macierz jest niekompletna."
                     logger.warning(last_error_flash + " Retrying...")
                     ok_proba = False # Oznacz próbę jako nieudaną

        except Exception as e: # Złap inne błędy podczas losowania
            last_error_flash = f"Próba {proba + 1} nieudana z powodu wyjątku: {e}"
            logger.error(last_error_flash, exc_info=True)
            ok_proba = False # Oznacz próbę jako nieudaną

        # Pętla 'for proba' przejdzie do następnej iteracji, jeśli ok_proba == False

    # Sprawdzenie po wszystkich próbach
    if not sukces_losowania_stref:
        final_error_msg = last_error_flash or f"Nie udało się wylosować poprawnej sekwencji stref po {MAX_PROB_LOSOWANIA_STREF} próbach."
        flash(final_error_msg + " Sprawdź ustawienia (szczególnie liczbę tur vs stref) lub spróbuj ponownie.", "danger")
        logger.error(f"Sequence Draw FAILED: Could not generate valid zone sequences after {MAX_PROB_LOSOWANIA_STREF} trials.")
        return redirect(url_for('losowanie')) # Wróć do panelu losowania
    # === KONIEC Losowania Sekwencji Stref z PĘTLĄ PONAWIANIA ===


    # === Zapis udanego losowania stref do bazy ===
    logger.info("Sequence Draw: Saving results to database...")
    wyniki_do_zapisu = []
    indeks_na_id = {i: z.id for i, z in enumerate(zawodnicy_do_losowania)} # Upewnij się, że to mapowanie jest aktualne

    # Sprawdź, czy wszystkie ID zawodników są poprawne (nie None)
    if None in indeks_na_id.values():
         flash("Błąd krytyczny: Niektórzy zawodnicy mają brakujące ID. Nie można zapisać losowania.", "danger")
         logger.critical(f"Sequence Draw Save Error: Found None ID in zawodnicy_do_losowania for comp {zawody_id}")
         return redirect(url_for('zawodnicy')) # Przekieruj do listy zawodników

    # Tworzenie obiektów WynikLosowania
    for idx, zawodnik_id in indeks_na_id.items():
        # Sprawdź, czy macierz ma odpowiedni wymiar (na wszelki wypadek)
        if idx < len(macierz_losowania):
            wynik = WynikLosowania(zawodnik_id=zawodnik_id, zawody_id=zawody_id)
            for t in range(liczba_tur):
                if t < len(macierz_losowania[idx]):
                    strefa = macierz_losowania[idx][t]
                    setattr(wynik, f'tura{t + 1}_strefa', strefa)
                    setattr(wynik, f'tura{t + 1}_sektor', None)
                    setattr(wynik, f'tura{t + 1}_stanowisko', None)
                else:
                    # To nie powinno się zdarzyć, jeśli macierz jest kompletna
                    logger.error(f"Sequence Draw Save Error: Matrix row {idx} too short for round {t+1}")
                    flash(f"Błąd wewnętrzny: Macierz losowania niekompletna dla zawodnika ID {zawodnik_id}.", "danger")
                    return redirect(url_for('losowanie'))
            wyniki_do_zapisu.append(wynik)
        else:
            logger.error(f"Sequence Draw Save Error: Matrix index {idx} out of bounds (matrix len: {len(macierz_losowania)})")
            flash("Błąd wewnętrzny: Niezgodność wymiarów macierzy losowania.", "danger")
            return redirect(url_for('losowanie'))

    # Zapis do bazy w transakcji
    if wyniki_do_zapisu:
        try:
            with db.session.begin_nested():
                # Usuń stare wyniki losowania DLA PEWNOŚCI
                WynikLosowania.query.filter_by(zawody_id=zawody_id).delete(synchronize_session=False)
                # Dodaj nowe wyniki
                db.session.add_all(wyniki_do_zapisu)
            db.session.commit()
            flash('Wylosowano sekwencje (strefy) dla pełnej obsady!', 'success')
            logger.info(f"Sequence Draw results saved successfully for comp {zawody_id}.")
        except Exception as e:
             db.session.rollback()
             logger.error(f"Sequence Draw: Error saving results to DB: {e}", exc_info=True)
             flash(f"Błąd podczas zapisywania wyników losowania stref: {e}", "danger")
             # Przekieruj do losowania, bo zapis się nie udał
             return redirect(url_for('losowanie'))
    else:
        # Ten komunikat nie powinien się pojawić, jeśli sukces_losowania_stref=True
        flash("Nie wygenerowano żadnych wyników losowania stref do zapisu (błąd wewnętrzny).", "error")
        logger.error(f"Sequence Draw: No results to save despite reported success for comp {zawody_id}.")
        return redirect(url_for('losowanie'))

    # Przekieruj do wyników losowania, gdzie użytkownik może kontynuować (losować sektory/stanowiska)
    return redirect(url_for('wyniki_losowania'))


@app.route('/losuj_sektory', methods=['POST'])
@login_required
@role_required('admin')
def losuj_sektory():
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    zawody_id = session['current_zawody_id']
    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).first()
    if not ustawienia:
        flash("Najpierw ustaw parametry zawodów!", "error")
        return redirect(url_for("ustawienia"))

    wyniki = WynikLosowania.query.filter_by(zawody_id=zawody_id).all()
    if not wyniki:
        flash("Najpierw wylosuj sekwencje (strefy)!", 'error')
        return redirect(url_for('losowanie'))

    if not any(getattr(w, 'tura1_strefa') for w in wyniki):
         flash("Wygląda na to, że strefy nie zostały wylosowane lub losowanie było niekompletne.", 'warning')
         return redirect(url_for('losowanie'))

    # Wyczyść sektory i stanowiska
    for wynik in wyniki:
        for tura in range(1, ustawienia.liczba_tur + 1):
            setattr(wynik, f'tura{tura}_sektor', None)
            setattr(wynik, f'tura{tura}_stanowisko', None)

    try:
        sukces_losowania_sektorow = _losuj_sektory(wyniki, ustawienia.liczba_tur, ustawienia)

        if sukces_losowania_sektorow:
            db.session.commit() # Zapisz tylko jeśli sukces
            flash('Wylosowano sektory!', 'success')
        else:
            db.session.rollback() # Odrzuć zmiany w obiektach `wyniki`
            flash('Losowanie sektorów nie powiodło się. Sprawdź komunikaty i ustawienia.', 'danger')

    except Exception as e:
        db.session.rollback()
        flash(f"Nieoczekiwany błąd podczas losowania sektorów: {e}", "danger")
        print(f"Nieoczekiwany błąd w losowaniu sektorów: {e}")

    return redirect(url_for('wyniki_losowania'))


@app.route('/losuj_stanowiska', methods=['POST'])
@login_required
@role_required('admin')
def losuj_stanowiska():
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    zawody_id = session['current_zawody_id']
    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).first()
    if not ustawienia:
        flash("Najpierw ustaw parametry zawodów!", "error")
        return redirect(url_for("ustawienia"))

    wyniki = WynikLosowania.query.filter_by(zawody_id=zawody_id).all()
    if not wyniki:
        flash("Najpierw wylosuj sekwencje i sektory!", 'error')
        return redirect(url_for('losowanie'))

    if not all(getattr(w, 'tura1_sektor') for w in wyniki): # Sprawdź czy *wszyscy* mają sektor w turze 1
         flash("Wygląda na to, że sektory nie zostały wylosowane dla wszystkich lub losowanie było niekompletne.", 'warning')
         return redirect(url_for('losowanie'))

     # Wyczyść tylko stanowiska
    for wynik in wyniki:
        for tura in range(1, ustawienia.liczba_tur + 1):
            setattr(wynik, f'tura{tura}_stanowisko', None)

    try:
        sukces_losowania_stanowisk = _losuj_stanowiska(wyniki, ustawienia.liczba_tur, ustawienia)

        if sukces_losowania_stanowisk:
            db.session.commit() # Zapisz tylko jeśli sukces
            flash('Wylosowano stanowiska!', 'success')
        else:
            db.session.rollback() # Odrzuć zmiany
            flash('Losowanie stanowisk nie powiodło się. Sprawdź komunikaty.', 'danger')

    except Exception as e:
        db.session.rollback()
        flash(f"Nieoczekiwany błąd podczas losowania stanowisk: {e}", "danger")
        print(f"Nieoczekiwany błąd w losowaniu stanowisk: {e}")

    return redirect(url_for('wyniki_losowania'))


@app.route('/wyniki_losowania', methods=['GET', 'POST'])
@login_required # Dostęp dla zalogowanych, edycja tylko dla admina
def wyniki_losowania():
    """
    Wyświetla wyniki losowania (strefy, sektory, stanowiska)
    i pozwala adminowi na ręczną edycję sektorów i stanowisk.
    Pokazuje też powtórzenia sekwencji StrefaSektor.
    """
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    logger.debug(f">>> Accessing wyniki_losowania. Method: {request.method}")
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    zawody_id = session['current_zawody_id']
    # Sprawdzenie, czy zawody istnieją
    aktywne_zawody = db.session.get(Zawody, zawody_id)
    if not aktywne_zawody:
        session.pop('current_zawody_id', None); session.pop('current_zawody_nazwa', None)
        flash('Wybrane zawody już nie istnieją. Wybierz inne.', 'warning')
        return redirect(url_for('zawody'))

    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).first()
    wyniki = WynikLosowania.query.options(db.joinedload(WynikLosowania.zawodnik))\
               .filter_by(zawody_id=zawody_id).all()

    # Sortuj wyniki dla spójnego wyświetlania
    def sort_key_display(wl):
        if wl.zawodnik: return (wl.zawodnik.is_puste_miejsce, wl.zawodnik.imie_nazwisko or "")
        return (True, "")
    wyniki.sort(key=sort_key_display)

    max_global_stanowisko = 0
    if ustawienia:
         try:
             max_global_stanowisko = (ustawienia.preferowana_liczba_stref *
                                     ustawienia.preferowana_liczba_sektorow *
                                     ustawienia.maks_liczba_stanowisk_w_sektorze)
         except (TypeError, AttributeError): max_global_stanowisko = 0
    else: logger.warning(f"No settings found for comp {zawody_id} when accessing wyniki_losowania.")

    # Użyj pustego FlaskForm dla ochrony CSRF w formularzu edycji
    form = FlaskForm()

    # --- Obsługa POST (ręczna edycja) ---
    if request.method == 'POST':
        logger.info(f"POST request to wyniki_losowania by user {current_user.username} (Role: {current_user.role})")
        if current_user.role != 'admin':
            flash('Nie masz uprawnień do ręcznego zapisywania zmian.', 'danger')
            return redirect(url_for('wyniki_losowania'))

        if not form.validate_on_submit(): # Sprawdzenie CSRF
             flash('Błąd walidacji formularza (CSRF). Spróbuj ponownie.', 'danger')
             return redirect(url_for('wyniki_losowania'))

        zmodyfikowano_sektor = False
        zmodyfikowano_stanowisko = False
        bledy = False
        wprowadzone_sektory = defaultdict(dict) # Do sprawdzania duplikatów sektorów
        wprowadzone_stanowiska = defaultdict(dict) # Do sprawdzania duplikatów stanowisk

        # Pętla przetwarzająca dane z formularza
        for wynik in wyniki:
            zawodnik_obj = wynik.zawodnik
            imie_nazwisko_display = (f"'{zawodnik_obj.imie_nazwisko}'" if zawodnik_obj and not zawodnik_obj.is_puste_miejsce else f"Puste (ID:{wynik.zawodnik_id})") if zawodnik_obj else f"Brak Zawodnika (ID:{wynik.zawodnik_id})"

            for tura in range(1, (ustawienia.liczba_tur + 1) if ustawienia else 1):
                # --- Obsługa SEKTORA ---
                pole_sektor_name = f'sektor_{wynik.id}_{tura}'
                sektor_str = request.form.get(pole_sektor_name)
                aktualny_sektor = getattr(wynik, f'tura{tura}_sektor', None) # Użyj getattr do bezpiecznego odczytu

                if sektor_str is not None:
                    nowy_sektor = sektor_str.strip().upper()
                    if nowy_sektor == "": nowy_sektor = None

                    if nowy_sektor is not None and not re.fullmatch(r'[A-Z]', nowy_sektor):
                        flash(f'Nieprawidłowy format sektora ("{sektor_str}") dla {imie_nazwisko_display} w turze {tura}. Oczekiwano jednej wielkiej litery (A-Z).', 'error')
                        bledy = True
                    else:
                        # Uproszczone logowanie potencjalnych duplikatów sektorów
                        if nowy_sektor is not None:
                             wprow_sek = wprowadzone_sektory.setdefault(tura, {})
                             if nowy_sektor in wprow_sek: logger.warning(f"Potential duplicate sector '{nowy_sektor}' in form for round {tura}.")
                             wprow_sek.setdefault(nowy_sektor, []).append(wynik.id)

                        if nowy_sektor != aktualny_sektor and not bledy:
                            try:
                                setattr(wynik, f'tura{tura}_sektor', nowy_sektor)
                                zmodyfikowano_sektor = True
                                logger.debug(f"Manually setting SEKTOR for WID:{wynik.id}, T:{tura} to '{nowy_sektor}' (was '{aktualny_sektor}')")
                            except AttributeError:
                                logger.error(f" setattr failed for tura{tura}_sektor, WID:{wynik.id}")
                                bledy = True # Traktuj to jako błąd

                # --- Obsługa STANOWISKA ---
                pole_stan_name = f'stanowisko_{wynik.id}_{tura}'
                stanowisko_str = request.form.get(pole_stan_name)
                aktualne_stanowisko = getattr(wynik, f'tura{tura}_stanowisko', None) # Użyj getattr

                if stanowisko_str is not None:
                    try:
                        if stanowisko_str.strip() == "": nowe_stanowisko = None
                        else:
                            nowe_stanowisko = int(stanowisko_str)
                            if max_global_stanowisko > 0 and not (1 <= nowe_stanowisko <= max_global_stanowisko):
                                flash(f'Nr stanowiska ({nowe_stanowisko}) poza zakresem [1-{max_global_stanowisko}] dla {imie_nazwisko_display} w turze {tura}.', 'error')
                                bledy = True; continue # Pomiń dalsze sprawdzanie dla tego pola
                            if nowe_stanowisko is not None:
                                if nowe_stanowisko in wprowadzone_stanowiska[tura]:
                                     konflikt_wynik_id = wprowadzone_stanowiska[tura][nowe_stanowisko]
                                     konflikt_wynik = next((w for w in wyniki if w.id == konflikt_wynik_id), None)
                                     konflikt_imie = (konflikt_wynik.zawodnik.imie_nazwisko if konflikt_wynik and konflikt_wynik.zawodnik and not konflikt_wynik.zawodnik.is_puste_miejsce else f"ID:{konflikt_wynik_id}") if konflikt_wynik else f"ID:{konflikt_wynik_id}"
                                     flash(f'Stanowisko {nowe_stanowisko} (tura {tura}) zostało przypisane więcej niż raz (do {imie_nazwisko_display} oraz {konflikt_imie})!', 'error')
                                     bledy = True
                                else: wprowadzone_stanowiska[tura][nowe_stanowisko] = wynik.id

                        if not bledy and nowe_stanowisko != aktualne_stanowisko:
                             try:
                                 setattr(wynik, f'tura{tura}_stanowisko', nowe_stanowisko)
                                 zmodyfikowano_stanowisko = True
                                 logger.debug(f"Manually setting STANOWISKO for WID:{wynik.id}, T:{tura} to {nowe_stanowisko} (was {aktualne_stanowisko})")
                             except AttributeError:
                                 logger.error(f" setattr failed for tura{tura}_stanowisko, WID:{wynik.id}"); bledy = True
                    except ValueError:
                        flash(f'Nieprawidłowa wartość (nie liczba: "{stanowisko_str}") dla stanowiska {imie_nazwisko_display} w turze {tura}!', 'error')
                        bledy = True; continue # Pomiń resztę dla tego pola

        # === Zapis do bazy ===
        if (zmodyfikowano_sektor or zmodyfikowano_stanowisko) and not bledy:
            try:
                db.session.commit()
                flash_msg_parts = []
                if zmodyfikowano_sektor: flash_msg_parts.append("sektory")
                if zmodyfikowano_stanowisko: flash_msg_parts.append("stanowiska")
                flash(f'Zapisano ręczne zmiany w: { " i ".join(flash_msg_parts) }!', 'success')
                logger.info(f"Admin {current_user.username} saved manual edits for draw results (comp {zawody_id}). Changed: {', '.join(flash_msg_parts)}")
            except Exception as e:
                 db.session.rollback()
                 logger.error(f"Error committing manual draw edits for comp {zawody_id}: {e}", exc_info=True)
                 flash(f"Błąd zapisu zmian do bazy danych: {e}", "danger")
        elif not (zmodyfikowano_sektor or zmodyfikowano_stanowisko) and not bledy:
             flash('Nie wprowadzono zmian w sektorach ani stanowiskach.', 'info')
        elif bledy:
             flash('Wystąpiły błędy walidacji. Popraw dane i spróbuj ponownie zapisać.', 'danger')

        return redirect(url_for('wyniki_losowania'))

    # --- Obsługa GET ---
    # Obliczanie powtórzeń sekwencji (StrefaSektor)
    powtorzenia = Counter()
    if ustawienia and wyniki:
        sekwencje_strefa_sektor = []
        for wynik in wyniki:
            if wynik.zawodnik and not wynik.zawodnik.is_puste_miejsce:
                sekwencja, valid_sequence = [], True
                for tura in range(1, ustawienia.liczba_tur + 1):
                    strefa = getattr(wynik, f'tura{tura}_strefa', None) # Bezpieczny odczyt w Pythonie
                    sektor = getattr(wynik, f'tura{tura}_sektor', None) # Bezpieczny odczyt w Pythonie
                    if strefa and sektor:
                        sekwencja.append(f"{strefa}{sektor}")
                    else:
                        valid_sequence = False; break
                if valid_sequence:
                    sekwencje_strefa_sektor.append("-".join(sekwencja))
        if sekwencje_strefa_sektor:
            powtorzenia = Counter(sekwencje_strefa_sektor)
            logger.debug(f"Calculated sequence repetitions: {dict(powtorzenia)}")
        else:
            logger.debug("No valid ZoneSector sequences found to count repetitions.")

    # Przekaż dane do szablonu
    return render_template('wyniki_losowania.html',
                           wyniki=wyniki,
                           ustawienia=ustawienia,
                           powtorzenia=powtorzenia, # Przekaż obliczone powtórzenia
                           form=form, # Przekaż pusty formularz dla CSRF
                           max_stanowisko=max_global_stanowisko)


@app.route('/generuj_pdf/<int:tura>')
@login_required
def generuj_pdf(tura):
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    zawody_id = session['current_zawody_id']
    zawody = Zawody.query.get_or_404(zawody_id)
    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).first()

    if not ustawienia or tura < 1 or tura > ustawienia.liczba_tur:
        flash('Nieprawidłowy numer tury lub brak ustawień.', 'error')
        return redirect(url_for('wyniki_losowania'))

    wyniki_q = WynikLosowania.query.options(db.joinedload(WynikLosowania.zawodnik)).filter_by(zawody_id=zawody_id).all()

    def get_sort_key(wynik):
        stanowisko = getattr(wynik, f'tura{tura}_stanowisko', None)
        return (stanowisko is None, stanowisko)
    wyniki_q.sort(key=get_sort_key)

    dane_do_tabeli = [["Nr Start.", "Zawodnik", "Strefa", "Sektor", "Stanowisko"]]
    for i, wynik in enumerate(wyniki_q):
        nr_startowy = i + 1
        imie_nazwisko = "Puste Miejsce"
        if wynik.zawodnik and not wynik.zawodnik.is_puste_miejsce:
             imie_nazwisko = wynik.zawodnik.imie_nazwisko

        strefa = getattr(wynik, f'tura{tura}_strefa', '') or '?'
        sektor = getattr(wynik, f'tura{tura}_sektor', '') or '?'
        stanowisko_val = getattr(wynik, f'tura{tura}_stanowisko', None)
        stanowisko = str(stanowisko_val) if stanowisko_val is not None else '?'

        dane_do_tabeli.append([str(nr_startowy), imie_nazwisko, strefa, sektor, stanowisko])

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    tytul_str = f"Lista Startowa - {zawody.nazwa} - Tura {tura}"
    story.append(Paragraph(tytul_str, styles['h1']))
    story.append(Spacer(1, 12))

    tabela = Table(dane_do_tabeli)
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 1), (-1,-1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ])
    tabela.setStyle(style)
    story.append(tabela)

    try:
        doc.build(story)
        buffer.seek(0)
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        # Użyj bezpiecznej nazwy pliku
        safe_nazwa_zawodow = "".join([c for c in zawody.nazwa if c.isalnum() or c in (' ', '-')]).rstrip()
        response.headers['Content-Disposition'] = f'inline; filename="lista_startowa_{safe_nazwa_zawodow}_tura_{tura}.pdf"'
        return response
    except Exception as e:
        flash(f"Błąd podczas generowania PDF: {e}", "danger")
        print(f"Błąd PDF: {e}")
        return redirect(url_for('wyniki_losowania'))


@app.route('/zawody', methods=['GET', 'POST'])
@login_required
def zawody():
    form = ZawodyForm()
    if request.method == 'POST' and current_user.role == 'admin':
        if form.validate_on_submit():
            istniejace_zawody = Zawody.query.filter(db.func.lower(Zawody.nazwa) == form.nazwa.data.lower()).first() # Ignoruj wielkość liter
            if istniejace_zawody:
                session['current_zawody_id'] = istniejace_zawody.id
                session['current_zawody_nazwa'] = istniejace_zawody.nazwa
                flash(f'Wybrano istniejące zawody: {istniejace_zawody.nazwa}', 'info')
            else:
                nowe_zawody = Zawody(nazwa=form.nazwa.data)
                db.session.add(nowe_zawody)
                try:
                    db.session.commit()
                    session['current_zawody_id'] = nowe_zawody.id
                    session['current_zawody_nazwa'] = nowe_zawody.nazwa
                    flash(f'Utworzono i wybrano nowe zawody: {nowe_zawody.nazwa}', 'success')
                    return redirect(url_for('ustawienia'))
                except Exception as e:
                     db.session.rollback()
                     flash(f"Błąd podczas tworzenia zawodów: {e}", "danger")
                     session.pop('current_zawody_id', None)
                     session.pop('current_zawody_nazwa', None)
            return redirect(url_for('index'))

    aktualne_zawody = None
    if 'current_zawody_id' in session:
        aktualne_zawody = Zawody.query.get(session['current_zawody_id'])
    wszystkie_zawody = Zawody.query.order_by(Zawody.nazwa).all()
    return render_template('zawody.html', form=form, zawody=aktualne_zawody, wszystkie_zawody=wszystkie_zawody)


@app.route('/zawody/wybierz/<int:zawody_id>', methods=['POST'])
@login_required
def wybierz_zawody(zawody_id):
    zawody_do_wyboru = Zawody.query.get_or_404(zawody_id)
    session['current_zawody_id'] = zawody_do_wyboru.id
    session['current_zawody_nazwa'] = zawody_do_wyboru.nazwa
    flash(f'Wybrano zawody: {zawody_do_wyboru.nazwa}', 'success')
    return redirect(url_for('index'))


@app.route('/zawody/usun', methods=['POST'])
@login_required
@role_required('admin')
def usun_zawody():
    zawody_id_do_us = request.form.get('zawody_id_do_usunięcia', type=int)
    if not zawody_id_do_us:
         flash('Nieprawidłowe żądanie usunięcia zawodów (brak ID).', 'danger')
         return redirect(url_for('zawody'))

    zawody = Zawody.query.get_or_404(zawody_id_do_us)
    nazwa_us = zawody.nazwa

    try:
        # Użyj cascade delete (jeśli skonfigurowane w modelach) lub usuń ręcznie
        Wynik.query.filter_by(zawody_id=zawody_id_do_us).delete()
        WynikLosowania.query.filter_by(zawody_id=zawody_id_do_us).delete()
        Zawodnik.query.filter_by(zawody_id=zawody_id_do_us).delete()
        UstawieniaZawodow.query.filter_by(zawody_id=zawody_id_do_us).delete()
        db.session.delete(zawody)
        db.session.commit()
        flash(f'Zawody "{nazwa_us}" i powiązane dane zostały usunięte!', 'success')
        if 'current_zawody_id' in session and session['current_zawody_id'] == zawody_id_do_us:
            session.pop('current_zawody_id', None)
            session.pop('current_zawody_nazwa', None)
    except Exception as e:
        db.session.rollback()
        flash(f'Błąd podczas usuwania zawodów "{nazwa_us}": {e}', 'danger')

    return redirect(url_for('zawody'))


@app.route('/ustawienia', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def ustawienia():
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    zawody_id = session['current_zawody_id']
    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).first()
    form = UstawieniaZawodowForm(obj=ustawienia)

    if form.validate_on_submit():
        # Sprawdź, czy wprowadzono zmiany w porównaniu do istniejących ustawień
        zmiana_w_ustawieniach = False
        if ustawienia:
             # Porównaj wartości z formularza z wartościami w obiekcie
             if (ustawienia.preferowana_liczba_stref != form.preferowana_liczba_stref.data or
                 ustawienia.preferowana_liczba_sektorow != form.preferowana_liczba_sektorow.data or
                 ustawienia.maks_liczba_stanowisk_w_sektorze != form.maks_liczba_stanowisk_w_sektorze.data or
                 ustawienia.liczba_tur != form.liczba_tur.data):
                  zmiana_w_ustawieniach = True
        else:
             zmiana_w_ustawieniach = True # Nowe ustawienia to zawsze zmiana

        if ustawienia:
            form.populate_obj(ustawienia)
            flash_msg = 'Ustawienia zaktualizowane!'
        else:
            ustawienia = UstawieniaZawodow(zawody_id=zawody_id)
            form.populate_obj(ustawienia)
            db.session.add(ustawienia)
            flash_msg = 'Ustawienia zapisane!'

        try:
            # Resetuj wyniki losowania tylko jeśli faktycznie zmieniono ustawienia wpływające na strukturę
            if zmiana_w_ustawieniach:
                 WynikLosowania.query.filter_by(zawody_id=zawody_id).delete()
                 db.session.commit()
                 flash(f'{flash_msg} Wyniki losowania zostały zresetowane z powodu zmiany ustawień.', 'success')
            else:
                 db.session.commit() # Zapisz, nawet jeśli nie było resetu (np. ponowne zapisanie tych samych wartości)
                 flash(f'{flash_msg} Nie wykryto zmian w strukturze, wyniki losowania nie zostały zresetowane.', 'info')

        except Exception as e:
            db.session.rollback()
            flash(f"Błąd podczas zapisywania ustawień: {e}", "danger")

        return redirect(url_for('ustawienia'))

    # Dla GET lub niepoprawnego POST
    # Oblicz aktualną pojemność, jeśli ustawienia istnieją
    aktualna_pojemnosc = 0
    if ustawienia:
         aktualna_pojemnosc = (ustawienia.preferowana_liczba_stref *
                               ustawienia.preferowana_liczba_sektorow *
                               ustawienia.maks_liczba_stanowisk_w_sektorze)

    return render_template('ustawienia.html', form=form, max_zawodnikow = UstawieniaZawodow.MAX_ZAWODNIKOW, aktualna_pojemnosc=aktualna_pojemnosc)


# --- Dynamiczny formularz dla wyników (klasa pomocnicza) ---
# Definiujemy klasę bazową, do której będziemy dynamicznie dodawać pola
class DynamicWynikForm(WynikForm):
    pass
# -----------------------------------------------------------

# ===============================================================
# === CAŁA FUNKCJA wprowadz_wyniki Z POPRAWIONĄ LOGIKĄ TURY ===
# ===============================================================
@app.route('/wprowadz_wyniki', methods=['GET', 'POST'])
@login_required
# @role_required('wagowy')
def wprowadz_wyniki():
    """
    Obsługuje wyświetlanie formularza do wprowadzania wyników wagowych dla wybranej tury
    oraz zapisywanie tych wyników. Wersja z poprawioną logiką ustalania tury i logowaniem.
    """
    print(f">>> Rozpoczęto funkcję wprowadz_wyniki() [Metoda: {request.method}]")

    # --- Podstawowe sprawdzenia ---
    if current_user.role not in ['admin', 'wagowy']:
         flash('Nie masz uprawnień do wprowadzania wyników.', 'danger')
         return redirect(url_for('index'))
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz lub utwórz zawody!', 'error')
        return redirect(url_for('zawody'))
    zawody_id = session['current_zawody_id']
    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).first()
    if not ustawienia:
        flash("Najpierw skonfiguruj ustawienia dla tych zawodów!", 'error')
        return redirect(url_for("ustawienia"))

    # === POCZĄTEK ZMIAN W LOGICE USTALANIA TURY ===
    wybrana_tura = None

    # Najpierw spróbuj pobrać turę z parametrów URL (dla GET i dla POST z formularza zapisu)
    # Akcja formularza zapisu powinna kierować na URL zawierający parametr tura=...
    wybrana_tura = request.args.get('tura', type=int)
    print(f"--- Odczytano 'tura' z request.args: {wybrana_tura}")

    # Sprawdzenie, czy tura jest poprawna (jeśli została odczytana)
    is_tura_valid = False
    if wybrana_tura is not None and (1 <= wybrana_tura <= ustawienia.liczba_tur):
        is_tura_valid = True
        print(f"--- Odczytana tura {wybrana_tura} jest poprawna.")

    # Jeśli metoda to POST i zawiera pole 'tura' w DANYCH formularza - to jest POST z formularza WYBORU tury
    if request.method == 'POST' and 'tura' in request.form:
        print("--- Wykryto POST z formularza WYBORU tury.")
        try:
            wybrana_tura_post = int(request.form['tura'])
            if 1 <= wybrana_tura_post <= ustawienia.liczba_tur:
                print(f"    Wybrano turę={wybrana_tura_post}. Przekierowuję do GET...")
                return redirect(url_for('wprowadz_wyniki', tura=wybrana_tura_post))
            else:
                flash(f"Wybrano nieprawidłowy numer tury ({wybrana_tura_post}). Dostępne: 1-{ustawienia.liczba_tur}.", "warning")
                is_tura_valid = False # Ustaw na False, żeby pokazać formularz wyboru ponownie
        except ValueError:
            flash("Nieprawidłowa wartość tury w formularzu wyboru.", "warning")
            is_tura_valid = False # Ustaw na False, żeby pokazać formularz wyboru ponownie

    # Jeśli po tych sprawdzeniach tura nadal nie jest poprawna, pokaż formularz wyboru
    if not is_tura_valid:
        print(f"--- Tura ({wybrana_tura}) odczytana z URL jest nieprawidłowa lub nie została podana. Pokazuję stronę wyboru tury.")
        form_wyboru = FlaskForm()
        return render_template('wybierz_ture.html', liczba_tur=ustawienia.liczba_tur, form=form_wyboru)

    # === KONIEC ZMIAN W LOGICE USTALANIA TURY ===

    # Od tego momentu mamy poprawną `wybrana_tura` zarówno dla GET jak i POST zapisu
    print(f"--- Przetwarzanie dla POPRAWNEJ tury: {wybrana_tura} ---")

    # --- Sprawdzenie kompletności losowania stanowisk dla wybranej tury ---
    liczba_oczekiwanych_wynikow = Zawodnik.query.filter_by(zawody_id=zawody_id).count()
    stanowisko_attr_name = f'tura{wybrana_tura}_stanowisko'
    liczba_wylosowanych_stanowisk = WynikLosowania.query.filter(
        WynikLosowania.zawody_id == zawody_id,
        getattr(WynikLosowania, stanowisko_attr_name).isnot(None)
    ).count()
    if liczba_wylosowanych_stanowisk < liczba_oczekiwanych_wynikow:
        brakujace = liczba_oczekiwanych_wynikow - liczba_wylosowanych_stanowisk
        flash(f"Losowanie stanowisk dla tury {wybrana_tura} jest niekompletne!", 'warning')
        flash(f"Oczekiwano {liczba_oczekiwanych_wynikow} stanowisk, znaleziono {liczba_wylosowanych_stanowisk} (brakuje {brakujace}). Uzupełnij w 'Wyniki Losowania'.", 'info')
        return redirect(url_for('wyniki_losowania'))
    print(f"--- Sprawdzono kompletność losowania stanowisk dla tury {wybrana_tura}: OK ({liczba_wylosowanych_stanowisk})")

    # --- Pobranie niezbędnych danych z bazy ---
    print("--- Pobieram dane: WynikiLosowania (z zawodnikami) i istniejące Wyniki...")
    wyniki_losowania = WynikLosowania.query.options(db.joinedload(WynikLosowania.zawodnik)).filter_by(zawody_id=zawody_id).all()
    istniejace_wyniki_tura = Wynik.query.filter_by(zawody_id=zawody_id, tura=wybrana_tura).all()
    mapa_wynikow = {w.zawodnik_id: w for w in istniejace_wyniki_tura}
    print(f"--- Pobrane dane: {len(wyniki_losowania)} wyników losowania, {len(istniejace_wyniki_tura)} istniejących wyników wagowych dla tury {wybrana_tura}.")

    # --- Dynamiczne DODAWANIE PÓL WAGA i BIG FISH (IntegerField dla gramów) do klasy formularza ---
    print("--- Rozpoczynam dynamiczne dodawanie/czyszczenie pól Waga/BigFish do klasy DynamicWynikForm ---")
    pola_dodane = set()
    wszystkie_id_ok = True
    print("    Czyszczenie starych dynamicznych pól...")
    licznik_usun = 0
    for attr_name in list(DynamicWynikForm.__dict__):
        if attr_name.startswith('zawodnik_'):
            delattr(DynamicWynikForm, attr_name)
            licznik_usun += 1
    print(f"    Usunięto {licznik_usun} starych pól dynamicznych.")
    print("    Dodawanie nowych pól dynamicznych...")
    for wynik_los in wyniki_losowania:
        if wynik_los.zawodnik and not wynik_los.zawodnik.is_puste_miejsce:
            zawodnik_id = wynik_los.zawodnik.id
            if zawodnik_id is None:
                 print(f"!!! KRYTYCZNE: zawodnik_id jest None dla WynikLosowania ID: {wynik_los.id}! Pomijam generowanie pól.")
                 wszystkie_id_ok = False; continue
            field_name_waga = f'zawodnik_{zawodnik_id}_tura{wybrana_tura}_waga'
            field_name_bigfish = f'zawodnik_{zawodnik_id}_tura{wybrana_tura}_bigfish'
            if not hasattr(DynamicWynikForm, field_name_waga):
                setattr(DynamicWynikForm, field_name_waga, IntegerField('Waga (g)', validators=[Optional(), NumberRange(min=0, message="Wartość nie może być ujemna.")]))
                pola_dodane.add(field_name_waga)
            if not hasattr(DynamicWynikForm, field_name_bigfish):
                setattr(DynamicWynikForm, field_name_bigfish, IntegerField('Big Fish (g)', validators=[Optional(), NumberRange(min=0, message="Wartość nie może być ujemna.")]))
                pola_dodane.add(field_name_bigfish)
    if not wszystkie_id_ok:
         flash("Błąd wewnętrzny podczas generowania formularza: niektórzy zawodnicy nie mają ID. Skontaktuj się z administratorem.", "danger")
         return redirect(url_for('wyniki_losowania'))
    print(f"--- Zakończono dynamiczną konfigurację klasy formularza. Dodano {len(pola_dodane)} nowych pól.")

    # --- Tworzenie INSTANCJI formularza ---
    # Przekazujemy dane z request.form tylko jeśli jest to POST dotyczący zapisu wyników
    form_data = request.form if request.method == 'POST' else None
    form = None
    try:
        # Ważne: Tworzymy formularz TUTAJ, używając klasy DynamicWynikForm, która została zmodyfikowana powyżej
        form = DynamicWynikForm(form_data)
        print(f"--- Utworzono instancję formularza DynamicWynikForm. Dane z POST: {bool(form_data)}")
    except Exception as e:
        print(f"!!! KRYTYCZNY BŁĄD podczas tworzenia instancji formularza: {e}")
        traceback.print_exc()
        flash(f"Wystąpił krytyczny błąd podczas tworzenia formularza: {e}", "danger")
        return redirect(url_for('wyniki_losowania'))

    # --- Wypełnianie formularza danymi z bazy (dla metody GET) ---
    if request.method == 'GET':
        print("--- Metoda GET: Wypełniam formularz istniejącymi danymi (w gramach)...")
        for wynik_los in wyniki_losowania:
             if wynik_los.zawodnik and not wynik_los.zawodnik.is_puste_miejsce:
                 zawodnik_id = wynik_los.zawodnik.id
                 if zawodnik_id is None:
                     print(f"    OSTRZEŻENIE (GET): Pomijam wynik losowania ID {wynik_los.id} - brak ID zawodnika.")
                     continue
                 field_name_waga = f'zawodnik_{zawodnik_id}_tura{wybrana_tura}_waga'
                 field_name_bigfish = f'zawodnik_{zawodnik_id}_tura{wybrana_tura}_bigfish'
                 istniejacy_wynik = mapa_wynikow.get(zawodnik_id)
                 if istniejacy_wynik:
                     waga_g_db = istniejacy_wynik.waga
                     bigfish_g_db = istniejacy_wynik.bigfish
                     # Ustawiamy .data w polach formularza (jeśli istnieją)
                     if hasattr(form, field_name_waga):
                         getattr(form, field_name_waga).data = waga_g_db
                     if hasattr(form, field_name_bigfish):
                         getattr(form, field_name_bigfish).data = bigfish_g_db
        print("--- Zakończono wypełnianie formularza dla GET.")

    # --- Obsługa zapisu wyników (POST) ---
    # Ten blok jest teraz osiągany poprawnie dla POST zapisu
    if request.method == 'POST':
        print(f"--- Metoda POST (zapis wyników): Rozpoczynam przetwarzanie formularza dla tury {wybrana_tura} ---")
        # Sprawdzenie uprawnień
        if current_user.role not in ['admin', 'wagowy']:
             flash('Nie masz uprawnień do zapisywania wyników.', 'danger')
             return redirect(url_for('wprowadz_wyniki', tura=wybrana_tura))
        print(f"--- Dane z request.form (do zapisu): {dict(request.form)}")

        # Używamy obiektu 'form', który został stworzony wcześniej z danymi z request.form
        if form.validate_on_submit():
            print("--- Formularz POST zapisu ZWALIDOWANY POPRAWNIE ---")
            zmodyfikowano_cos = False
            try:
                print("    Rozpoczynam iterację po wynikach losowania w celu zapisu...")
                for wynik_los in wyniki_losowania:
                    if wynik_los.zawodnik and not wynik_los.zawodnik.is_puste_miejsce:
                        zawodnik_id = wynik_los.zawodnik.id
                        if zawodnik_id is None:
                            print(f"    OSTRZEŻENIE (POST ZAPIS): Pomijam wynik losowania ID {wynik_los.id} - brak ID zawodnika.")
                            continue

                        field_name_waga = f'zawodnik_{zawodnik_id}_tura{wybrana_tura}_waga'
                        field_name_bigfish = f'zawodnik_{zawodnik_id}_tura{wybrana_tura}_bigfish'
                        # Odwołujemy się do pól w już istniejącym obiekcie 'form'
                        pole_waga = getattr(form, field_name_waga, None)
                        pole_bigfish = getattr(form, field_name_bigfish, None)

                        waga_g_form = pole_waga.data if pole_waga and pole_waga.data is not None else 0
                        bigfish_g_form = pole_bigfish.data if pole_bigfish and pole_bigfish.data is not None else 0
                        waga_g = int(waga_g_form)
                        bigfish_g = int(bigfish_g_form)

                        print(f"    ---> Dla Zawodnik ID: {zawodnik_id}, Odczytano z form: Waga={waga_g}g, BigFish={bigfish_g}g")

                        wynik = mapa_wynikow.get(zawodnik_id)
                        is_new_record = False
                        if not wynik:
                            wynik = Wynik(zawodnik_id=zawodnik_id, zawody_id=zawody_id, tura=wybrana_tura)
                            db.session.add(wynik)
                            mapa_wynikow[zawodnik_id] = wynik
                            is_new_record = True
                            print(f"        Nowy rekord Wynik zostanie utworzony.")

                        waga_przed = wynik.waga if not is_new_record and hasattr(wynik, 'waga') else 'N/A (nowy)'
                        bigfish_przed = wynik.bigfish if not is_new_record and hasattr(wynik, 'bigfish') else 'N/A (nowy)'
                        print(f"        W bazie/obiekcie przed modyfikacją: Waga={waga_przed}g, BigFish={bigfish_przed}g")

                        # Sprawdzenie czy wartość się zmieniła
                        zmiana_wagi = is_new_record or (hasattr(wynik, 'waga') and wynik.waga != waga_g)
                        zmiana_bigfish = is_new_record or (hasattr(wynik, 'bigfish') and wynik.bigfish != bigfish_g)

                        if zmiana_wagi:
                             print(f"        * ZMIANA WAGI: {waga_przed}g -> {waga_g}g")
                             wynik.waga = waga_g
                             zmodyfikowano_cos = True
                        if zmiana_bigfish:
                             print(f"        * ZMIANA BIG FISH: {bigfish_przed}g -> {bigfish_g}g")
                             wynik.bigfish = bigfish_g
                             zmodyfikowano_cos = True

                        if not zmiana_wagi and not zmiana_bigfish and not is_new_record:
                             print(f"        Brak zmian dla tego zawodnika.")

                print(f"    Zakończono pętlę. Flaga zmodyfikowano_cos = {zmodyfikowano_cos}")

                if zmodyfikowano_cos:
                    print("    Wykryto zmiany, próbuję zapisać do bazy danych (db.session.commit())...")
                    db.session.commit()
                    flash(f'Wyniki dla tury {wybrana_tura} zostały zapisane/zaktualizowane!', 'success')
                    print("    Zapis do bazy zakończony sukcesem.")
                else:
                    flash('Nie wprowadzono żadnych zmian w wynikach dla tej tury.', 'info')
                    print("    Nie wykryto żadnych zmian, nie wykonano zapisu do bazy.")

                print("--- POST zapisu: Zakończono pomyślnie, przekierowuję (PRG)... ---")
                return redirect(url_for('wprowadz_wyniki', tura=wybrana_tura))

            except Exception as e:
                print(f"!!! BŁĄD WEWNĄTRZ TRY...EXCEPT podczas zapisu: {e}")
                db.session.rollback()
                traceback.print_exc()
                flash(f'Wystąpił poważny błąd podczas zapisywania wyników: {e}. Zmiany nie zostały zapisane.', 'danger')
                # Pozwól na ponowne renderowanie formularza z błędami (poniżej)

        else: # Błąd walidacji formularza POST zapisu
             print(f"!!! Formularz NIE przeszedł walidacji. Błędy: {form.errors}")
             flash('Formularz zawiera błędy. Popraw podświetlone pola i spróbuj ponownie.', 'danger')
             # Pozwól na ponowne renderowanie formularza z błędami (poniżej)


    # --- Renderowanie szablonu (dla GET lub jeśli POST miał błędy) ---
    print(f"--- Renderuję szablon 'wprowadz_wyniki.html' dla tury {wybrana_tura} (Metoda: {request.method}) ---")

    def get_sort_key_wprowadz(wynik_los):
        sektor = getattr(wynik_los, f'tura{wybrana_tura}_sektor', '') or 'ŻŻŻ'
        stanowisko = getattr(wynik_los, f'tura{wybrana_tura}_stanowisko', float('inf'))
        return (sektor, stanowisko)

    wyniki_losowania_do_wysw = sorted(wyniki_losowania, key=get_sort_key_wprowadz)

    if form is None:
        print("!!! OSTRZEŻENIE: Obiekt 'form' jest None podczas renderowania szablonu. Tworzę pusty.")
        form = DynamicWynikForm() # Utwórz pusty formularz, aby szablon się nie wywalił

    return render_template('wprowadz_wyniki.html',
                           form=form,
                           wyniki_losowania=wyniki_losowania_do_wysw,
                           tura=wybrana_tura,
                           ustawienia=ustawienia)
# ===============================================================
# === KONIEC FUNKCJI wprowadz_wyniki ===

# Plik: app/routes.py (fragment)

# ... (importy i inne funkcje bez zmian) ...

@app.route('/wyniki_koncowe')
@login_required
def wyniki_koncowe():
    """Oblicza i wyświetla wyniki końcowe zawodów wg punktów sektorowych
    dla wszystkich zapisanych zawodników, grupując tych z wagą > 0 na górze.
    Waga do obliczenia punktów w turze = Waga(form) + BigFish(form) (0 pkt za 0 wagę).
    Uwzględnia tylko tury z wprowadzonymi wynikami wagowymi."""
    # Użyj loggera aplikacji Flask lub standardowego
    logger = current_app.logger if current_app else logging.getLogger(__name__)

    logger.info(">>> Accessing wyniki_koncowe() [Grouped >0, NO FILTER, Sector Pts (W+BF -> 0pts for 0w), Active Rounds]")

    # --- Sprawdzenie podstawowe ---
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody.', 'warning')
        return redirect(url_for('zawody'))
    zawody_id = session['current_zawody_id']

    # --- Pobranie danych ---
    competition_obj = Zawody.query.get_or_404(zawody_id)
    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).first()

    # Sprawdzenia ustawień
    if not ustawienia:
         flash("Brak ustawień dla tych zawodów. Nie można obliczyć punktów sektorowych.", "danger")
         logger.error(f"Cannot calculate final results for competition {zawody_id}: Settings missing.")
         return redirect(url_for('ustawienia'))
    if not ustawienia.liczba_tur or ustawienia.liczba_tur <= 0:
         flash("Nieprawidłowa liczba tur w ustawieniach. Nie można obliczyć wyników.", "danger")
         logger.error(f"Cannot calculate final results for competition {zawody_id}: Invalid number of rounds ({ustawienia.liczba_tur}).")
         return redirect(url_for('ustawienia'))

    logger.info(f"--- Calculating final results for: {competition_obj.nazwa} (ID: {zawody_id}) ---")
    logger.info(f"--- Max configured rounds: {ustawienia.liczba_tur}")

    wyniki_koncowe_lista = []
    rundy_aktywne = []

    try:
        # 1. Pobierz wszystkich rzeczywistych zawodników
        zawodnicy_real = Zawodnik.query.filter_by(zawody_id=zawody_id, is_puste_miejsce=False).all()
        if not zawodnicy_real:
            flash("Brak zapisanych zawodników (nie-pustych) dla tych zawodów.", "info")
            logger.info(f"No real competitors found for competition {zawody_id}. Rendering empty results.")
            return render_template('wyniki_koncowe.html', zawody=competition_obj, wyniki_koncowe=[], ustawienia=ustawienia, rundy_aktywne=[])
        zawodnicy_dict = {z.id: {'imie_nazwisko': z.imie_nazwisko} for z in zawodnicy_real}
        logger.info(f"--- Found {len(zawodnicy_dict)} real competitors.")

        # Inicjalizacja aggregated_results dla wszystkich zawodników
        aggregated_results = {}
        for zid, zinfo in zawodnicy_dict.items():
            aggregated_results[zid] = {
                'id': zid, 'imie_nazwisko': zinfo['imie_nazwisko'], 'total_points': 0.0,
                'total_waga': 0, 'total_bigfish': 0, 'max_bigfish': 0,
                'tury_data': { t: {'punkty': None, 'waga': None, 'bigfish': None, 'sektor': None, 'strefa': None, 'stanowisko': None}
                              for t in range(1, ustawienia.liczba_tur + 1)}
            }
        logger.debug(f"--- Initialized aggregated_results structure for {len(aggregated_results)} competitors.")

        # 2. Identyfikacja Aktywnych Tur
        logger.info("--- Identifying active rounds (with weight results)...")
        for t in range(1, ustawienia.liczba_tur + 1):
            if db.session.query(Wynik.id).filter_by(zawody_id=zawody_id, tura=t).limit(1).scalar() is not None:
                rundy_aktywne.append(t)
        logger.info(f"--- Active rounds identified: {rundy_aktywne}")

        if not rundy_aktywne:
            flash("Nie wprowadzono jeszcze żadnych wyników wagowych dla żadnej tury.", "info")
            wyniki_koncowe_lista = [
                { 'id': zid, 'imie_nazwisko': zinfo['imie_nazwisko'], 'miejsce': 1, 'total_points': 0.0, 'total_waga': 0, 'total_bigfish': 0, 'max_bigfish': 0, 'tury_data': {} }
                for zid, zinfo in zawodnicy_dict.items() ]
            wyniki_koncowe_lista.sort(key=lambda x: x['imie_nazwisko'].lower())
            logger.info("--- No active rounds found. Returning initial state for all competitors.")
            return render_template('wyniki_koncowe.html', zawody=competition_obj, wyniki_koncowe=wyniki_koncowe_lista, ustawienia=ustawienia, rundy_aktywne=rundy_aktywne)

        # 3. Pobierz wyniki losowania dla aktywnych tur
        losowanie_all = WynikLosowania.query.options(db.joinedload(WynikLosowania.zawodnik)).filter_by(zawody_id=zawody_id).all()
        losowanie_lookup = {}
        for wl in losowanie_all:
            if wl.zawodnik_id in zawodnicy_dict:
                for t in rundy_aktywne:
                    sektor = getattr(wl, f'tura{t}_sektor', None)
                    strefa = getattr(wl, f'tura{t}_strefa', None)
                    stanowisko = getattr(wl, f'tura{t}_stanowisko', None)
                    if sektor:
                        losowanie_lookup[(wl.zawodnik_id, t)] = {'sektor': sektor, 'strefa': strefa, 'stanowisko': stanowisko}
        logger.debug(f"--- Created draw lookup map for active rounds: {len(losowanie_lookup)} entries.")

        # 4. Pobierz wyniki wagowe dla aktywnych tur
        wyniki_wagowe_all = Wynik.query.filter(
            Wynik.zawody_id == zawody_id,
            Wynik.zawodnik_id.in_(zawodnicy_dict.keys()),
            Wynik.tura.in_(rundy_aktywne)
        ).all()
        wyniki_lookup = {}
        for w in wyniki_wagowe_all:
            wyniki_lookup[(w.zawodnik_id, w.tura)] = {
                'waga': w.waga if w.waga is not None else 0,
                'bigfish': w.bigfish if w.bigfish is not None else 0
            }
        logger.debug(f"--- Created weight results lookup map for active rounds: {len(wyniki_lookup)} entries.")

        # 5. Obliczanie punktów sektorowych dla aktywnych tur
        logger.info(f"--- Starting calculation of sector points for ACTIVE rounds: {rundy_aktywne} (Weight for points = Waga+BigFish, 0 pts for 0 weight)...")
        for tura in rundy_aktywne:
            logger.info(f"  Processing ACTIVE ROUND {tura}:")
            dane_tury_po_sektorach = defaultdict(list)

            for zawodnik_id in zawodnicy_dict:
                klucz_losowania = (zawodnik_id, tura)
                losowanie_data = losowanie_lookup.get(klucz_losowania)
                waga_tura_oryg = 0
                bf_tura_oryg = 0
                waga_do_punktow = 0 # Domyślnie 0

                if losowanie_data and losowanie_data.get('sektor'):
                    sektor = losowanie_data['sektor']
                    klucz_wyniku = (zawodnik_id, tura)
                    wynik_data_tura = wyniki_lookup.get(klucz_wyniku, {'waga': 0, 'bigfish': 0})
                    waga_tura_oryg = wynik_data_tura.get('waga', 0)
                    bf_tura_oryg = wynik_data_tura.get('bigfish', 0)
                    waga_do_punktow = waga_tura_oryg + bf_tura_oryg # Kluczowa suma

                    # Dodaj do danych sektora z wagą do punktów
                    dane_tury_po_sektorach[sektor].append({'zawodnik_id': zawodnik_id, 'waga': waga_do_punktow})

                    # Zapisz szczegóły tury (oryginalne wagi)
                    aggregated_results[zawodnik_id]['tury_data'][tura]['sektor'] = sektor
                    aggregated_results[zawodnik_id]['tury_data'][tura]['strefa'] = losowanie_data.get('strefa')
                    aggregated_results[zawodnik_id]['tury_data'][tura]['stanowisko'] = losowanie_data.get('stanowisko')
                    aggregated_results[zawodnik_id]['tury_data'][tura]['waga'] = waga_tura_oryg
                    aggregated_results[zawodnik_id]['tury_data'][tura]['bigfish'] = bf_tura_oryg
                else:
                    # Zawodnik bez sektora
                    logger.warning(f"    Competitor ID {zawodnik_id} has no sector assigned in ACTIVE round {tura}. Will receive 0 points implicitly for this round if they had 0 weight, or calculated points if weight>0 (but data missing here).")
                    # W tej wersji logiki, jeśli nie ma sektora, nie trafi do obliczeń punktów sektorowych.
                    # Jeśli nie ma też wpisu w wyniki_lookup (czyli miał 0g), to jego total_points się nie zmieni (zostanie 0).
                    # Jeśli *miał* wagę > 0 ale nie ma sektora (błąd danych!), to jego punkty za tę turę nie zostaną dodane.
                    # Należy zapewnić spójność danych (każdy z wynikiem>0 powinien mieć sektor).
                    if tura in aggregated_results[zawodnik_id]['tury_data']:
                        aggregated_results[zawodnik_id]['tury_data'][tura]['punkty'] = None # Brak punktów
                        aggregated_results[zawodnik_id]['tury_data'][tura]['sektor'] = "Brak"


            # Oblicz punkty dla każdego sektora - użyje zmodyfikowanej funkcji
            for sektor, wyniki_sektora in dane_tury_po_sektorach.items():
                logger.info(f"    -> Calculating points for Sector {sektor} (Round {tura}) using summed weight (W+BF) and 0pts-for-0-weight rule")
                if not wyniki_sektora: continue

                punkty_sektorowe_tura = oblicz_punkty_sektorowe(wyniki_sektora) # Używa nowej logiki

                # Dodaj obliczone punkty (0 dla tych z wagą 0)
                for zawodnik_id, punkty in punkty_sektorowe_tura.items():
                    if zawodnik_id in aggregated_results:
                        # Sprawdź czy punkty nie są None, zanim dodasz (chociaż funkcja powinna zwracać 0.0)
                        if punkty is not None:
                            aggregated_results[zawodnik_id]['total_points'] += punkty
                            aggregated_results[zawodnik_id]['tury_data'][tura]['punkty'] = punkty
                        else:
                            logger.warning(f"      Received None points for zawodnik {zawodnik_id} from oblicz_punkty_sektorowe, expected 0.0 or more.")
                            aggregated_results[zawodnik_id]['tury_data'][tura]['punkty'] = 0.0 # Bezpieczniej ustawić 0
                    else:
                         logger.error(f"!!! CRITICAL INTERNAL ERROR: Calculated points for unknown competitor ID: {zawodnik_id} in sector {sektor}, round {tura}")

        # 7. Agreguj sumę wag (WAGA + BIGFISH) i max big fish
        logger.info("--- Aggregating total weights (Waga + BigFish) and finding max big fish for active rounds...")
        for (zawodnik_id, tura), wynik_data in wyniki_lookup.items():
             if zawodnik_id in aggregated_results:
                  waga_tura = wynik_data.get('waga', 0)
                  bigfish_tura = wynik_data.get('bigfish', 0)
                  # Suma wag do klasyfikacji generalnej
                  aggregated_results[zawodnik_id]['total_waga'] += (waga_tura + bigfish_tura)
                  # Suma big fish i max big fish
                  aggregated_results[zawodnik_id]['total_bigfish'] += bigfish_tura
                  if bigfish_tura > aggregated_results[zawodnik_id]['max_bigfish']:
                      aggregated_results[zawodnik_id]['max_bigfish'] = bigfish_tura
                  # Zapis oryginalnych wartości w tury_data
                  if tura in aggregated_results[zawodnik_id]['tury_data']:
                      aggregated_results[zawodnik_id]['tury_data'][tura]['waga'] = waga_tura
                      aggregated_results[zawodnik_id]['tury_data'][tura]['bigfish'] = bigfish_tura

        # 8. Konwertuj do listy
        wyniki_koncowe_lista = list(aggregated_results.values())
        logger.debug(f"--- Aggregated results before sort (count: {len(wyniki_koncowe_lista)}): {wyniki_koncowe_lista}")

        # 9. Sortuj listę z dodatkowym kryterium grupowania
        if wyniki_koncowe_lista:
            logger.info("--- Sorting final results (grouping non-zero weight first)...")
            wyniki_koncowe_lista.sort(key=lambda x: (
                x['total_waga'] == 0,      # True (1) dla wagi 0, False (0) dla wagi > 0
                x['total_points'],          # Rosnąco
                -x['total_waga'],         # Malejąco
                -x['max_bigfish'],        # Malejąco
                x['imie_nazwisko'].lower()  # Alfabetycznie
            ))
            logger.info(f"--- Sorted {len(wyniki_koncowe_lista)} competitors.")

            # 10. Dodaj miejsce
            for i, wynik in enumerate(wyniki_koncowe_lista):
                 wynik['miejsce'] = i + 1
            logger.debug(f"--- Final list with places added (BEFORE render): {wyniki_koncowe_lista}")

    except Exception as e: # Obsługa błędów
        logger.error(f"!!! ERROR during final results calculation: {e}", exc_info=True)
        traceback.print_exc()
        flash(f"Wystąpił błąd podczas obliczania wyników końcowych: {e}", "danger")
        wyniki_koncowe_lista = []
        rundy_aktywne = []

    # 11. Renderowanie szablonu
    logger.info(f"--- Rendering wyniki_koncowe.html template with active rounds: {rundy_aktywne} and final results count: {len(wyniki_koncowe_lista)}")
    return render_template('wyniki_koncowe.html',
                           zawody=competition_obj,
                           wyniki_koncowe=wyniki_koncowe_lista,
                           ustawienia=ustawienia,
                           rundy_aktywne=rundy_aktywne)

# =======================================================================
# === KONIEC WYNIKÓW KOŃCOWYCH (Grupowanie>0, 0pkt za 0w) ===
# =======================================================================

# ==========================================================
# === PUBLICZNY WIDOK WYNIKÓW ZAWODÓW ===
# ==========================================================
@app.route('/public/zawody/<int:zawody_id>')
def public_view(zawody_id):
    """
    Wyświetla publiczny, niezabezpieczony widok wyników zawodów,
    zawierający klasyfikację ogólną i szczegółowe wyniki sektorowe.
    """
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    logger.info(f">>> Accessing PUBLIC VIEW for competition ID: {zawody_id}")

    try:
        # --- Pobranie podstawowych danych ---
        competition_obj = Zawody.query.get_or_404(zawody_id)
        ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).first()

        if not ustawienia:
             # Można wyświetlić stronę z informacją lub przekierować, ale tu pokażemy info
             flash("Brak konfiguracji (ustawień) dla tych zawodów.", "warning")
             logger.warning(f"Public view aborted for comp {zawody_id}: Settings missing.")
             # Render a simple template or return an error message page
             return render_template('public_zawody_error.html', zawody=competition_obj, message="Brak ustawień dla tych zawodów.")
        if not ustawienia.liczba_tur or ustawienia.liczba_tur <= 0:
             flash("Nieprawidłowa liczba tur w ustawieniach.", "warning")
             logger.warning(f"Public view aborted for comp {zawody_id}: Invalid number of rounds ({ustawienia.liczba_tur}).")
             return render_template('public_zawody_error.html', zawody=competition_obj, message="Nieprawidłowa liczba tur w ustawieniach.")

        logger.info(f"--- Public View: Processing '{competition_obj.nazwa}' (ID: {zawody_id}) ---")
        logger.info(f"--- Configured rounds: {ustawienia.liczba_tur}")

        # --- Pobranie zawodników (tylko realnych) ---
        zawodnicy_real = Zawodnik.query.filter_by(zawody_id=zawody_id, is_puste_miejsce=False).all()
        if not zawodnicy_real:
            logger.info(f"No real competitors found for public view (comp {zawody_id}).")
            # Można zwrócić pustą stronę lub stronę z informacją
            return render_template('public_zawody.html',
                                   zawody=competition_obj,
                                   ustawienia=ustawienia,
                                   klasyfikacja_ogolna=[],
                                   wyniki_sektorowe_wg_tur={},
                                   rundy_aktywne=[],
                                   message="Brak zapisanych zawodników w tych zawodach.")

        zawodnicy_dict = {z.id: {'imie_nazwisko': z.imie_nazwisko} for z in zawodnicy_real if z.id is not None}
        logger.info(f"--- Found {len(zawodnicy_dict)} real competitors.")

        # --- Identyfikacja aktywnych tur ---
        active_rounds_query = db.session.query(Wynik.tura).filter_by(zawody_id=zawody_id).distinct().all()
        rundy_aktywne = sorted([r[0] for r in active_rounds_query if r[0] is not None and 1 <= r[0] <= ustawienia.liczba_tur])
        logger.info(f"--- Active rounds identified: {rundy_aktywne}")

        # --- Inicjalizacja struktur wyników ---
        # Dla klasyfikacji ogólnej
        aggregated_results = {}
        for zid, zinfo in zawodnicy_dict.items():
            aggregated_results[zid] = {
                'id': zid, 'imie_nazwisko': zinfo['imie_nazwisko'], 'total_points': 0.0,
                'total_waga': 0, 'total_bigfish': 0, 'max_bigfish': 0, 'rounds_counted': 0,
                'tury_data': { t: {'punkty': None, 'waga': None, 'bigfish': None, 'sektor': None, 'strefa': None, 'stanowisko': None}
                              for t in range(1, ustawienia.liczba_tur + 1)}
            }
        # Dla wyników sektorowych
        wyniki_sektorowe_wg_tur = defaultdict(lambda: defaultdict(list))
        # Struktura: {tura: {sektor: [{'id', 'imie_nazwisko', 'waga', 'bigfish', 'punkty_sektorowe', 'miejsce_w_sektorze', 'waga_do_punktow'}, ...]}}

        # --- Jeśli nie ma aktywnych tur, zwróć pusty widok ---
        if not rundy_aktywne:
            logger.info("--- No active rounds found. Rendering empty/initial state.")
            klasyfikacja_ogolna_lista = [
                { 'id': zid, 'imie_nazwisko': zinfo['imie_nazwisko'], 'miejsce': 1, 'total_points': 0.0, 'total_waga': 0, 'total_bigfish': 0, 'max_bigfish': 0, 'rounds_counted': 0, 'tury_data': aggregated_results[zid]['tury_data'] }
                for zid, zinfo in zawodnicy_dict.items() ]
            klasyfikacja_ogolna_lista.sort(key=lambda x: x['imie_nazwisko'].lower())
            for i, wynik in enumerate(klasyfikacja_ogolna_lista): wynik['miejsce'] = i + 1
            return render_template('public_zawody.html',
                                   zawody=competition_obj,
                                   ustawienia=ustawienia,
                                   klasyfikacja_ogolna=klasyfikacja_ogolna_lista,
                                   wyniki_sektorowe_wg_tur={},
                                   rundy_aktywne=[],
                                   message="Nie wprowadzono jeszcze żadnych wyników wagowych.")

        # --- Pobranie danych losowania i wyników wagowych (optymalizacja) ---
        logger.debug("--- Fetching draw and weight data for active rounds...")
        losowanie_all = WynikLosowania.query.filter(
            WynikLosowania.zawody_id == zawody_id,
            WynikLosowania.zawodnik_id.in_(zawodnicy_dict.keys())
        ).all()
        losowanie_lookup = {} # {(zid, tura): {sektor, strefa, stanowisko}}
        for wl in losowanie_all:
            if wl.zawodnik_id is None: continue
            for t in rundy_aktywne:
                losowanie_lookup[(wl.zawodnik_id, t)] = {
                    'sektor': getattr(wl, f'tura{t}_sektor', None),
                    'strefa': getattr(wl, f'tura{t}_strefa', None),
                    'stanowisko': getattr(wl, f'tura{t}_stanowisko', None)}

        wyniki_wagowe_all = Wynik.query.filter(
            Wynik.zawody_id == zawody_id,
            Wynik.zawodnik_id.in_(zawodnicy_dict.keys()),
            Wynik.tura.in_(rundy_aktywne)
        ).all()
        wyniki_lookup = {} # {(zid, tura): {'waga': w, 'bigfish': bf}}
        for w in wyniki_wagowe_all:
             if w.zawodnik_id is None or w.tura is None: continue
             wyniki_lookup[(w.zawodnik_id, w.tura)] = {
                'waga': w.waga if w.waga is not None else 0,
                'bigfish': w.bigfish if w.bigfish is not None else 0 }
        logger.debug(f"--- Draw lookup: {len(losowanie_lookup)} entries. Weight lookup: {len(wyniki_lookup)} entries.")


        # === Przetwarzanie danych dla każdej AKTYWNEJ tury ===
        logger.info(f"--- Processing active rounds: {rundy_aktywne}...")
        for tura in rundy_aktywne:
            logger.info(f"  Processing Round {tura}...")
            # 1. Przygotuj dane do obliczenia punktów sektorowych dla tej tury
            dane_do_punktacji_tura = defaultdict(list) # {sektor: [{'zawodnik_id': id, 'waga': w+bf}, ...]}
            dane_zawodnikow_tura = {} # {zid: {'waga', 'bigfish', 'sektor', 'stanowisko', 'strefa', 'waga_do_punktow'}}

            for zawodnik_id, zinfo in zawodnicy_dict.items():
                los_data = losowanie_lookup.get((zawodnik_id, tura), {})
                wag_data = wyniki_lookup.get((zawodnik_id, tura), {'waga': 0, 'bigfish': 0})
                sektor = los_data.get('sektor')
                waga_oryg = wag_data.get('waga', 0)
                bf_oryg = wag_data.get('bigfish', 0)
                waga_do_punktow = waga_oryg + bf_oryg

                # Zapisz dane zawodnika na potrzeby wyników sektorowych
                dane_zawodnikow_tura[zawodnik_id] = {
                    'id': zawodnik_id,
                    'imie_nazwisko': zinfo['imie_nazwisko'],
                    'waga': waga_oryg,
                    'bigfish': bf_oryg,
                    'sektor': sektor,
                    'strefa': los_data.get('strefa'),
                    'stanowisko': los_data.get('stanowisko'),
                    'waga_do_punktow': waga_do_punktow,
                    'punkty_sektorowe': None, # Zostaną uzupełnione później
                    'miejsce_w_sektorze': None # Zostaną uzupełnione później
                }

                # Dodaj do danych do punktacji tylko jeśli ma sektor
                if sektor:
                    dane_do_punktacji_tura[sektor].append({
                        'zawodnik_id': zawodnik_id,
                        'waga': waga_do_punktow
                    })
                else:
                     logger.warning(f"    Round {tura}: Competitor ID {zawodnik_id} has no sector assigned.")

            # 2. Oblicz punkty sektorowe dla każdego sektora w tej turze
            punkty_tura_wszystkie = {} # {zid: punkty}
            for sektor, wyniki_w_sektorze in dane_do_punktacji_tura.items():
                logger.debug(f"    Calculating points for Sector {sektor} (Round {tura})...")
                punkty_sektora = oblicz_punkty_sektorowe(wyniki_w_sektorze)
                punkty_tura_wszystkie.update(punkty_sektora)
                logger.debug(f"      -> Sector {sektor} points: {punkty_sektora}")

            # 3. Zaktualizuj wyniki ogólne ORAZ zapisz punkty w `dane_zawodnikow_tura`
            for zawodnik_id, dane_zaw in dane_zawodnikow_tura.items():
                punkty = punkty_tura_wszystkie.get(zawodnik_id)
                # Jeśli zawodnik nie miał sektora, punkty będą None (bo nie było go w punkty_tura_wszystkie)
                # Jeśli miał sektor i 0 wagę, punkty będą 0.0
                # Jeśli miał sektor i >0 wagę, punkty będą > 0.0

                dane_zaw['punkty_sektorowe'] = punkty # Zapisz punktację dla tego sektora/tury

                if punkty is not None:
                     aggregated_results[zawodnik_id]['total_points'] += punkty
                     aggregated_results[zawodnik_id]['rounds_counted'] += 1
                # Zapisz szczegóły w `aggregated_results` (dla tabeli ogólnej)
                if tura in aggregated_results[zawodnik_id]['tury_data']:
                    aggregated_results[zawodnik_id]['tury_data'][tura]['punkty'] = punkty
                    aggregated_results[zawodnik_id]['tury_data'][tura]['waga'] = dane_zaw['waga']
                    aggregated_results[zawodnik_id]['tury_data'][tura]['bigfish'] = dane_zaw['bigfish']
                    aggregated_results[zawodnik_id]['tury_data'][tura]['sektor'] = dane_zaw['sektor']
                    aggregated_results[zawodnik_id]['tury_data'][tura]['strefa'] = dane_zaw['strefa']
                    aggregated_results[zawodnik_id]['tury_data'][tura]['stanowisko'] = dane_zaw['stanowisko']


            # 4. Przygotuj dane do tabel sektorowych DLA TEJ TURY
            logger.debug(f"    Preparing sector detail data for round {tura}...")
            zawodnicy_wg_sektora_tura = defaultdict(list)
            for zid, dane_zaw in dane_zawodnikow_tura.items():
                if dane_zaw['sektor']: # Dodaj tylko tych, którzy mieli sektor
                    zawodnicy_wg_sektora_tura[dane_zaw['sektor']].append(dane_zaw)

                        # 5. Posortuj zawodników w każdym sektorze i przypisz miejsca W SEKTORZE
            for sektor, lista_zawodnikow in zawodnicy_wg_sektora_tura.items():
                # Sortuj wg wagi do punktów (malejąco), potem ID (dla stabilności)
                lista_zawodnikow.sort(key=lambda x: (x['waga_do_punktow'], x['id']), reverse=True)

                # Przypisz miejsca w sektorze (obsługa remisów wagowych)
                aktualne_miejsce_sektor = 1
                i = 0
                while i < len(lista_zawodnikow):
                    aktualna_waga_sektor = lista_zawodnikow[i]['waga_do_punktow']
                    # Znajdź grupę remisującą wagą
                    j = i
                    while j < len(lista_zawodnikow) and lista_zawodnikow[j]['waga_do_punktow'] == aktualna_waga_sektor:
                        j += 1

                    # === POPRAWKA 1: Zdefiniuj liczbę remisujących ===
                    liczba_remisujacych_sektor = j - i

                    # Przypisz to samo miejsce wszystkim w grupie
                    for k in range(i, j):
                        lista_zawodnikow[k]['miejsce_w_sektorze'] = aktualne_miejsce_sektor

                    # Przesuń miejsce startowe dla następnej grupy
                    # === POPRAWKA 2: Użyj poprawnej zmiennej ===
                    aktualne_miejsce_sektor += liczba_remisujacych_sektor

                    # Przesuń indeks
                    i = j

                # Zapisz posortowaną listę z miejscami w głównej strukturze
                wyniki_sektorowe_wg_tur[tura][sektor] = lista_zawodnikow
                logger.debug(f"      -> Sector {sektor} (Round {tura}) details prepared: {len(lista_zawodnikow)} competitors.")


        # === Agregacja końcowa i sortowanie klasyfikacji ogólnej ===
        logger.info("--- Aggregating final weights and sorting overall classification...")
        for (zawodnik_id, tura), wag_data in wyniki_lookup.items():
             if zawodnik_id in aggregated_results and tura in rundy_aktywne:
                  waga_tura = wag_data.get('waga', 0)
                  bigfish_tura = wag_data.get('bigfish', 0)
                  aggregated_results[zawodnik_id]['total_waga'] += (waga_tura + bigfish_tura)
                  aggregated_results[zawodnik_id]['total_bigfish'] += bigfish_tura
                  if bigfish_tura > aggregated_results[zawodnik_id]['max_bigfish']:
                      aggregated_results[zawodnik_id]['max_bigfish'] = bigfish_tura

        klasyfikacja_ogolna_lista = list(aggregated_results.values())
        if klasyfikacja_ogolna_lista:
            klasyfikacja_ogolna_lista.sort(key=lambda x: (
                x['total_waga'] <= 0, x['total_points'], -x['total_waga'],
                -x['max_bigfish'], x['imie_nazwisko'].lower()
            ))
            for i, wynik in enumerate(klasyfikacja_ogolna_lista):
                wynik['miejsce'] = i + 1
            logger.debug(f"--- Overall classification sorted. Top result: {klasyfikacja_ogolna_lista[0] if klasyfikacja_ogolna_lista else 'N/A'}")

        # Sort sector keys within each round for consistent display
        wyniki_sektorowe_posortowane = {}
        for tura, sektory_dane in wyniki_sektorowe_wg_tur.items():
            wyniki_sektorowe_posortowane[tura] = dict(sorted(sektory_dane.items()))

    except Exception as e:
        logger.error(f"!!! ERROR during public view generation for comp {zawody_id}: {e}", exc_info=True)
        traceback.print_exc()
        # Attempt to render an error page
        competition_obj_err = Zawody.query.get(zawody_id) # Try to get name at least
        return render_template('public_zawody_error.html',
                               zawody=competition_obj_err,
                               message=f"Wystąpił wewnętrzny błąd serwera podczas generowania wyników: {e}")

    # === Renderowanie szablonu ===
    logger.info(f"--- Rendering public_zawody.html for comp {zawody_id} ---")
    return render_template('public_zawody.html',
                           zawody=competition_obj,
                           ustawienia=ustawienia,
                           klasyfikacja_ogolna=klasyfikacja_ogolna_lista,
                           wyniki_sektorowe_wg_tur=wyniki_sektorowe_posortowane, # Przekaż posortowane
                           rundy_aktywne=rundy_aktywne)

# ==========================================================
# === KONIEC PUBLICZNEGO WIDOKU ===
# ==========================================================
# app/routes.py

# ... (istniejące importy) ...
from flask import render_template, url_for, current_app # Upewnij się, że masz render_template, url_for
from app import app, db # Importuj app i db
from app.models import Zawody # Importuj model Zawody
import logging

# ... (istniejące trasy, w tym public_view) ...

# ==========================================================
# === PUBLICZNA LISTA ZAWODÓW ===
# ==========================================================

# !!! WAŻNE: Upewnij się, że TUTAJ NIE MA @login_required !!!
@app.route('/public')
def public_lista_zawodow():
    """Wyświetla publiczną listę zawodów z linkami do ich wyników."""
    logger = current_app.logger if current_app else logging.getLogger(__name__)
    logger.info(">>> Accessing PUBLIC competition list page")
    zawody_lista = [] # Domyślna pusta lista
    error_message = None

    try:
        # Pobierz wszystkie zawody, posortowane np. po nazwie malejąco (lub ID malejąco dla najnowszych)
        zawody_lista = Zawody.query.order_by(Zawody.nazwa.asc()).all()
        # lub: zawody_lista = Zawody.query.order_by(Zawody.id.desc()).all()

        logger.debug(f"--- Found {len(zawody_lista)} competitions for public list.")

    except Exception as e:
        logger.error(f"!!! ERROR fetching competition list for public view: {e}", exc_info=True)
        error_message = "Wystąpił błąd podczas pobierania listy zawodów."
        # Możesz zwrócić prosty błąd lub renderować szablon z komunikatem błędu

    # Renderuj szablon, przekazując listę zawodów
    return render_template('public_lista_zawodow.html',
                           zawody_lista=zawody_lista,
                           error_message=error_message)

# ==========================================================
# === KONIEC PUBLICZNEJ LISTY ===
# ==========================================================

# ... (reszta tras) ...
