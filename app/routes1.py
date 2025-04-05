from flask import render_template, request, redirect, url_for, flash, session
from app import app, db, bcrypt
from app.models import Zawodnik, Zawody, WynikLosowania, UstawieniaZawodow, User
from app.forms import ZawodnikForm, ZawodyForm, UstawieniaZawodowForm, RegistrationForm, LoginForm, WynikForm
from flask_login import login_user, current_user, logout_user, login_required
import random
import itertools
from functools import wraps
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer, Paragraph
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from collections import Counter


# Dekorator do sprawdzania roli
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash('Nie masz uprawnień do tej strony.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def _losuj_sektory(wyniki, liczba_tur):
    """
    Przydziela sektory w ramach wylosowanych stref, dbając o równomierny rozkład.
    """
    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=session['current_zawody_id']).first()
    liczba_stref = ustawienia.preferowana_liczba_stref
    liczba_sektorow_w_strefie = ustawienia.preferowana_liczba_sektorow
    maks_liczba_stanowisk = ustawienia.maks_liczba_stanowisk_w_sektorze

    # Mapa strefa -> lista sektorów (sektory są unikalne w obrębie zawodów)
    strefa_do_sektorow = {}
    for strefa_num in range(1, liczba_stref + 1):
        strefa_str = str(strefa_num)
        sektory = []
        for i in range(liczba_sektorow_w_strefie):
            # Obliczamy literę sektora (A, B, C, ...) globalnie
            litera = chr(65 + (strefa_num - 1) * liczba_sektorow_w_strefie + i)  # 65 to ASCII dla 'A'
            sektory.append(litera)
        strefa_do_sektorow[strefa_str] = sektory


    for tura in range(1, liczba_tur + 1):
        # Słownik do zliczania zawodników w sektorach w *tej* turze i strefie:
        # Klucz: (strefa, sektor), wartość: liczba zawodników/pustych miejsc
        przydzialy_w_sektorach = {}

        for wynik in wyniki:
            tura_sektor_attr = f'tura{tura}_sektor'

            # Jeśli sektor *już jest* przydzielony w tej turze, to przechodzimy do kolejnego wyniku
            if getattr(wynik, tura_sektor_attr) is not None:
                continue

            strefa = getattr(wynik, f'tura{tura}_strefa') #Pobieramy wylosowaną strefę dla danej tury

            # Pobieramy listę *wszystkich* dostępnych (możliwych) sektorów w *tej* strefie
            dostepne_sektory = strefa_do_sektorow[strefa]


            # *** ZLICZANIE ZAWODNIKÓW W SEKTORACH (w tej turze i strefie) ***

            # 1. Inicjalizacja słownika:
            #    - Musimy zainicjalizować licznik dla *każdego* sektora w *danej* strefie.
            #    - Inicjalizujemy *zerami*.
            for s in dostepne_sektory: #Iterujemy po *dostępnych* sektorach w wylosowanej strefie
                if (strefa, s) not in przydzialy_w_sektorach: #Jeśli nie ma jeszcze przydziałów w tej strefie
                    przydzialy_w_sektorach[(strefa, s)] = 0 #To dla każdego sektora w tej strefie, ustawiamy 0

            # 2. Zliczanie:
            #    - Iterujemy po *wszystkich* wynikach losowania.
            #    - Sprawdzamy, czy dany wynik (`inny_wynik`) ma już przydzielony sektor w *tej* turze.
            #    - *Jeśli tak*, to zwiększamy licznik dla odpowiedniego sektora (i strefy!).
            for inny_wynik in wyniki:
                inny_sektor = getattr(inny_wynik, f'tura{tura}_sektor')
                inna_strefa = getattr(inny_wynik, f'tura{tura}_strefa')  # WAŻNE: Musimy sprawdzić strefę!
                if inny_sektor and inna_strefa == strefa:  # *Tylko* jeśli strefa się zgadza!
                    przydzialy_w_sektorach[(inna_strefa, inny_sektor)] += 1

            # 3. Sortowanie i wybór:
            #    - Sortujemy dostępne sektory *rosnąco* według liczby przydzielonych zawodników.
            #      Kluczem sortowania jest *drugi* element krotki (czyli liczba zawodników).
            posortowane_sektory = sorted(
                [(sektor, przydzialy_w_sektorach[(strefa, sektor)]) for sektor in dostepne_sektory],
                key=lambda item: item[1]
            )
            # Wybieramy pierwszy element z posortowanej listy (czyli sektor z najmniejszą liczbą zawodników).
            wylosowany_sektor = posortowane_sektory[0][0]
            setattr(wynik, tura_sektor_attr, wylosowany_sektor) #Przypisujemy do wyniku.

def _losuj_stanowiska(wyniki, liczba_tur):
    """
    Przydziela stanowiska w ramach wylosowanych stref i sektorów.
    """
    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=session['current_zawody_id']).first()
    liczba_stref = ustawienia.preferowana_liczba_stref
    liczba_sektorow_w_strefie = ustawienia.preferowana_liczba_sektorow
    maks_liczba_stanowisk = ustawienia.maks_liczba_stanowisk_w_sektorze

    print("=== _losuj_stanowiska ===")  # DEBUG
    print("Liczba tur:", liczba_tur)  # DEBUG
    print("Ustawienia:", ustawienia)  # DEBUG

    # Mapa sektor -> lista numerów stanowisk (kluczem jest string, np. "A", "B", itd.)
    sektor_do_numerow = {}
    for strefa_num in range(1, liczba_stref + 1):
        for i in range(liczba_sektorow_w_strefie):
            sektor = chr(65 + (strefa_num - 1) * liczba_sektorow_w_strefie + i)  # A, B, C, ...
            # Poprawne generowanie zakresu stanowisk
            start = ((strefa_num - 1) * liczba_sektorow_w_strefie + i) * maks_liczba_stanowisk + 1
            stop = start + maks_liczba_stanowisk
            sektor_do_numerow[sektor] = list(range(start, stop))

    print("SEKTOR DO NUMEROW:", sektor_do_numerow)  # DEBUG - Sprawdź, czy to jest OK

    for tura in range(1, liczba_tur + 1):
        print(f"=== Tura: {tura} ===")  # DEBUG
        # Kopia mapy sektor_do_numerow dla każdej tury
        sektor_do_numerow_kopia = {k: v[:] for k, v in sektor_do_numerow.items()}  # Kopia słownika!
        for wynik in wyniki:
            tura_stanowisko_attr = f'tura{tura}_stanowisko'

            # Jeśli stanowisko zostało już wylosowane, to pomijamy
            if getattr(wynik, tura_stanowisko_attr) is not None:
                continue

            sektor = getattr(wynik, f'tura{tura}_sektor')
            strefa = getattr(wynik, f'tura{tura}_strefa') #Pobieramy strefę
            print(f"  Zawodnik/Puste: {wynik.zawodnik.imie_nazwisko if wynik.zawodnik else 'Puste'}, Sektor: {sektor}, Strefa: {strefa}")  # DEBUG
            if sektor is not None:  #Sprawdzamy czy wylosowano sektor
                dostepne_stanowiska = sektor_do_numerow_kopia[sektor]  # Używamy kopii!
                print(f"    Dostępne stanowiska w sektorze {sektor}: {dostepne_stanowiska}")  # DEBUG
                if not dostepne_stanowiska:
                    print("    !!! BRAK DOSTĘPNYCH STANOWISK !!!")  # DEBUG
                    # Dodatkowe informacje:
                    print("    Aktualna tura:", tura)
                    print("    Zawodnik/Puste:", wynik.zawodnik.imie_nazwisko if wynik.zawodnik else 'Puste')
                    print("    Sektor:", sektor)
                    print("    Strefa:", strefa)

                    print("    Wszystkie wyniki losowania:")  # DEBUG - Stan *przed* błędem
                    for w in wyniki:
                        print(f"        Wynik ID: {w.id}, Zawodnik: {w.zawodnik.imie_nazwisko if w.zawodnik else 'Puste'}, Tura 1: (Strefa: {w.tura1_strefa}, Sektor: {w.tura1_sektor}, Stanowisko: {w.tura1_stanowisko}), Tura 2: (Strefa: {w.tura2_strefa}, Sektor: {w.tura2_sektor}, Stanowisko: {w.tura2_stanowisko}), Tura 3: (Strefa: {w.tura3_strefa}, Sektor: {w.tura3_sektor}, Stanowisko: {w.tura3_stanowisko}), Tura 4: (Strefa: {w.tura4_strefa}, Sektor: {w.tura4_sektor}, Stanowisko: {w.tura4_stanowisko})") # Dodany print
                    return #Przerywamy działanie funkcji.

                wylosowane_stanowisko = random.choice(dostepne_stanowiska)  # Tu jest błąd, jeśli lista pusta
                print(f"    Wylosowane stanowisko: {wylosowane_stanowisko}")  # DEBUG
                setattr(wynik, tura_stanowisko_attr, wylosowane_stanowisko)
                sektor_do_numerow_kopia[sektor].remove(wylosowane_stanowisko)  # Usuwamy z *kopii*!

@app.route('/register', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('Konto zostało utworzone!', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', title='Rejestracja', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Logowanie nieudane. Sprawdź nazwę użytkownika i hasło.', 'danger')
    return render_template('login.html', title='Logowanie', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/")
@app.route("/index")
@login_required
def index():
    if 'current_zawody_id' in session:
        zawody = Zawody.query.get(session['current_zawody_id'])
        if zawody:
            return render_template('index.html', zawody=zawody)
    return render_template('index.html', zawody=None)

@app.route("/admin")
@login_required
@role_required('admin')
def admin_panel():
    return render_template('admin.html')

@app.route('/users')
@login_required
@role_required('admin')
def user_list():
    users = User.query.all()
    return render_template('user_list.html', users=users)

@app.route('/zawodnicy', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def zawodnicy():
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    form = ZawodnikForm()
    if form.validate_on_submit():
        zawodnik = Zawodnik(imie_nazwisko=form.imie_nazwisko.data, zawody_id=session['current_zawody_id'])
        db.session.add(zawodnik)
        db.session.commit()
        flash('Zawodnik dodany!', 'success')
        # Po dodaniu zawodnika, usuwamy wyniki losowania, by wymusić ponowne losowanie
        WynikLosowania.query.filter_by(zawody_id=session['current_zawody_id']).delete()
        db.session.commit()
        return redirect(url_for('zawodnicy'))

    zawodnicy_lista = Zawodnik.query.filter_by(zawody_id=session['current_zawody_id']).all()
    return render_template('zawodnicy.html', form=form, zawodnicy=zawodnicy_lista)

@app.route('/zawodnicy/usun/<int:id>', methods=['POST'])
@login_required
@role_required('admin')
def usun_zawodnika(id):
    zawodnik = Zawodnik.query.get_or_404(id)
    if zawodnik.zawody_id != session['current_zawody_id']:
        flash("Nie można usunąć zawodnika z innych zawodów.", 'error')
        return redirect(url_for('zawodnicy'))

    db.session.delete(zawodnik)
    db.session.commit()
    flash('Zawodnik usunięty!', 'success')
     # Po usunięciu zawodnika usuwamy wyniki losowania
    WynikLosowania.query.filter_by(zawody_id=session['current_zawody_id']).delete()
    db.session.commit()
    return redirect(url_for('zawodnicy'))

@app.route('/losowanie', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def losowanie():
  return render_template('losowanie.html')

@app.route('/losuj_sekwencje', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def losuj_sekwencje():
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=session['current_zawody_id']).first()
    if not ustawienia:
        flash("Najpierw ustaw parametry zawodów!", "error")
        return redirect(url_for("ustawienia"))

    if request.method == 'POST':
        zawodnicy = Zawodnik.query.filter_by(zawody_id=session['current_zawody_id']).all()
        liczba_zawodnikow = len([z for z in zawodnicy if not z.is_puste_miejsce])

        liczba_stref = ustawienia.preferowana_liczba_stref
        liczba_sektorow = ustawienia.preferowana_liczba_sektorow
        maks_stanowisk = ustawienia.maks_liczba_stanowisk_w_sektorze
        liczba_tur = ustawienia.liczba_tur

        max_zawodnicy = liczba_stref * liczba_sektorow * maks_stanowisk
        if liczba_zawodnikow > max_zawodnicy:
            flash(f'Za dużo zawodników! Maksymalna liczba to {max_zawodnicy} przy obecnych ustawieniach.', 'error')
            return redirect(url_for('losowanie'))

        # Usuń stare wyniki (powiązane z *aktualnymi* zawodami)
        WynikLosowania.query.filter_by(zawody_id=session['current_zawody_id']).delete()
        db.session.commit()

        # Dodaj/usuń puste miejsca *przed* losowaniem
        puste_miejsca = Zawodnik.query.filter_by(zawody_id=session['current_zawody_id'], is_puste_miejsce=True).all()
        liczba_pustych_miejsc = len(puste_miejsca)
        roznica =  max_zawodnicy - liczba_zawodnikow - liczba_pustych_miejsc

        if roznica > 0:
            for _ in range(roznica):
                pusty_zawodnik = Zawodnik(imie_nazwisko=None, zawody_id=session['current_zawody_id'], is_puste_miejsce=True)
                db.session.add(pusty_zawodnik)

        elif roznica < 0:
            for p in puste_miejsca:
              if roznica == 0:
                break
              db.session.delete(p)
              roznica += 1
        db.session.commit()


        # Pobierz *wszystkich* zawodników (łącznie z pustymi miejscami)
        wszyscy_zawodnicy = Zawodnik.query.filter_by(zawody_id=session['current_zawody_id']).all()

        #  Obliczamy limit zawodników na strefę w każdej turze:
        limit_na_strefe = (liczba_zawodnikow + liczba_pustych_miejsc) // liczba_stref
        if (liczba_zawodnikow + liczba_pustych_miejsc) % liczba_stref != 0: #jeśli są resztki
          limit_na_strefe += 1

        print("=== LOSUJ SEKWENCJE ===")  # DEBUG
        print("Liczba zawodników (w tym puste):", len(wszyscy_zawodnicy))  # DEBUG
        print("Liczba stref:", liczba_stref)  # DEBUG
        print("Liczba tur:", liczba_tur)  # DEBUG
        print("Limit na strefę:", limit_na_strefe)  # DEBUG

        # LOSOWANIE STREF (deterministyczny algorytm)
        wyniki = []
        # Najpierw tworzymy puste obiekty WynikLosowania i *zapisujemy* je do bazy
        for zawodnik in wszyscy_zawodnicy:
            wynik = WynikLosowania(zawodnik_id=zawodnik.id, zawody_id=session['current_zawody_id'])
            wyniki.append(wynik)
        db.session.add_all(wyniki)
        db.session.commit()

        # Pobierz *wszystkie* wyniki losowania (teraz już z ID)
        wyniki = WynikLosowania.query.filter_by(zawody_id=session['current_zawody_id']).all()

        # 1. Wygeneruj wszystkie *możliwe* permutacje stref:
        permutacje = list(itertools.permutations([str(i) for i in range(1, liczba_stref + 1)]))

        # 2. *Wymieszaj* listę permutacji:
        random.shuffle(permutacje)

        # 3. *Powiel* listę permutacji, jeśli trzeba:
        if liczba_tur > liczba_stref:  # Wtedy na pewno trzeba powielić
          # Zmieniamy na:
          permutacje = (permutacje * (liczba_tur // len(permutacje) + 1))[:liczba_tur] # By lista miała długość tury, a nie ilości zawodników.

        # Przypisz strefy
        for i, wynik in enumerate(wyniki):  # Iterujemy po *obiektach* WynikLosowania (z ID)
            # Bierzemy *kolejną* permutację z listy (z zawijaniem):
            # permutacja = permutacje[i % len(permutacje)] # Stare, błędne podejście
            # Nowe podejscie, bierzemy i-tą permutację
            permutacja = permutacje[i % len(permutacje)]
            print(f"Zawodnik/Puste: {wynik.zawodnik.imie_nazwisko if wynik.zawodnik else 'Puste'}, Permutacja: {permutacja}") #DEBUG
            for tura in range(1, liczba_tur + 1):
                strefa = permutacja[tura - 1]  # Pobieramy strefę z *permutacji*
                print(f"  Tura {tura}: Strefa {strefa}")  # DEBUG
                setattr(wynik, f'tura{tura}_strefa', str(strefa)) #ustawiamy atrybut

        db.session.commit()  # Zapis *po* wylosowaniu stref (ale *przed* losowaniem sektorów i stanowisk)

        flash('Wylosowano sekwencje (strefy)!', 'success')
        return redirect(url_for('wyniki_losowania'))

    return render_template('losowanie.html') #Przycisk Losuj Sekwencje przenosi do tego widoku.

@app.route('/losuj_sektory', methods=['POST'])
@login_required
@role_required('admin')
def losuj_sektory():
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=session['current_zawody_id']).first()
    if not ustawienia:
        flash("Najpierw ustaw parametry zawodów!", "error")
        return redirect(url_for("ustawienia"))

    # Pobierz wszystkie wyniki losowania dla aktualnych zawodów (czyli wylosowane już strefy)
    wyniki = WynikLosowania.query.filter_by(zawody_id=session['current_zawody_id']).all()

    # Sprawdź, czy w ogóle są jakieś wyniki (czy wylosowano już strefy)
    if not wyniki:
        flash("Najpierw wylosuj sekwencje (strefy)!", 'error')
        return redirect(url_for('losowanie'))  # Wracamy do strony losowania

    # Losuj sektory dla każdej tury
    for tura in range(1, ustawienia.liczba_tur + 1):
      _losuj_sektory(wyniki, ustawienia.liczba_tur)  # Losowanie sektorów
      db.session.commit() # Zapisujemy zmiany dla każdej tury

    flash('Wylosowano sektory!', 'success')
    return redirect(url_for('wyniki_losowania'))

@app.route('/losuj_stanowiska', methods=['POST']) #Widok dla losowania stanowisk
@login_required
@role_required('admin')
def losuj_stanowiska():
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=session['current_zawody_id']).first()
    if not ustawienia:
        flash("Najpierw ustaw parametry zawodów!", "error")
        return redirect(url_for("ustawienia"))

    wyniki = WynikLosowania.query.filter_by(zawody_id=session['current_zawody_id']).all()
    if not wyniki:
        flash("Najpierw wylosuj sekwencje i sektory!", 'error')
        return redirect(url_for('losowanie'))  # Wracamy do strony losowania

    for tura in range(1, ustawienia.liczba_tur+1):
      _losuj_stanowiska(wyniki, ustawienia.liczba_tur) #Losowanie stanowisk
      db.session.commit()#Zapis
    flash('Wylosowano stanowiska!', 'success')
    return redirect(url_for('wyniki_losowania'))

@app.route('/wyniki_losowania', methods=['GET', 'POST'])
@login_required
def wyniki_losowania():
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=session['current_zawody_id']).first()
    wyniki = WynikLosowania.query.filter_by(zawody_id=session['current_zawody_id']).all()

    if request.method == 'POST':
        #Obsługa POST, czyli zapisu danych
        for wynik in wyniki:
          for tura in range(1, ustawienia.liczba_tur +1):
            tura_stanowisko_attr = f'tura{tura}_stanowisko'
            pole_name = f'stanowisko_{wynik.id}_{tura}'
            stanowisko_str = request.form.get(pole_name)
            if stanowisko_str:
                try:
                    stanowisko = int(stanowisko_str)
                except ValueError:
                    flash(f'Nieprawidłowa wartość dla zawodnika {wynik.zawodnik.imie_nazwisko if wynik.zawodnik else "Puste miejsce"} w turze {tura}!', 'error')
                    continue

                if 1<= stanowisko <= (ustawienia.preferowana_liczba_sektorow * ustawienia.maks_liczba_stanowisk_w_sektorze):
                  setattr(wynik, tura_stanowisko_attr, stanowisko)
                else:
                  flash(f'Nieprawidłowa wartość dla zawodnika {wynik.zawodnik.imie_nazwisko if wynik.zawodnik else "Puste miejsce"} w turze {tura}!', 'error')

        db.session.commit()
        flash('Zapisano stanowiska!', 'success')

        #Obliczanie powtórzeń sekwencji:
    sekwencje = []
    for wynik in wyniki:
        sekwencja = []
        for tura in range(1,(ustawienia.liczba_tur + 1) if ustawienia else 1):
            strefa = getattr(wynik, f'tura{tura}_strefa','') or ''
            sektor = getattr(wynik, f'tura{tura}_sektor', '') or ''
            sekwencja.append(str(strefa) + str(sektor))
        sekwencje.append("-".join(sekwencja))

    powtorzenia = Counter(sekwencje)
    return render_template('wyniki_losowania.html', wyniki=wyniki, ustawienia=ustawienia, powtorzenia=powtorzenia) #Poprawione!


@app.route('/generuj_pdf/<int:tura>')
@login_required
def generuj_pdf(tura):
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=session['current_zawody_id']).first()
    if tura < 1 or tura > ustawienia.liczba_tur:
        flash('Nieprawidłowy numer tury', 'error')
        return redirect(url_for('wyniki_losowania'))

    wyniki = db.session.query(Zawodnik.imie_nazwisko, WynikLosowania).outerjoin(Zawodnik, Zawodnik.id == WynikLosowania.zawodnik_id).filter(WynikLosowania.zawody_id == session['current_zawody_id']).all()

    dane_do_tabeli = [["Numer", "Zawodnik", "Strefa", "Sektor", "Stanowisko"]]
    for i, (imie_nazwisko, wynik) in enumerate(wyniki):
        if imie_nazwisko is None:
            imie_nazwisko = "Puste Miejsce"
        if tura == 1:
            dane_do_tabeli.append([str(i + 1), imie_nazwisko, wynik.tura1_strefa, wynik.tura1_sektor, str(wynik.tura1_stanowisko)])
        if tura == 2:
            dane_do_tabeli.append([str(i + 1), imie_nazwisko, wynik.tura2_strefa, wynik.tura2_sektor, str(wynik.tura2_stanowisko)])
        if tura == 3:
             dane_do_tabeli.append([str(i + 1), imie_nazwisko, wynik.tura3_strefa, wynik.tura3_sektor, str(wynik.tura3_stanowisko)])
        if tura == 4:
             dane_do_tabeli.append([str(i + 1), imie_nazwisko, wynik.tura4_strefa, wynik.tura4_sektor, str(wynik.tura4_stanowisko)])

    nazwa_pliku = f"tura_{tura}.pdf"
    doc = SimpleDocTemplate(nazwa_pliku, pagesize=letter)
    story = []
    tabela = Table(dane_do_tabeli)
    tabela.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(tabela)
    doc.build(story)

    return redirect(url_for('static', filename=nazwa_pliku))

@app.route('/zawody', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def zawody():
    form = ZawodyForm()
    if form.validate_on_submit():
        zawody = Zawody.query.filter_by(nazwa=form.nazwa.data).first()
        if zawody:
            # Jeśli zawody o tej nazwie już istnieją, wybieramy je jako aktualne
            session['current_zawody_id'] = zawody.id
            session['current_zawody_nazwa'] = zawody.nazwa
            flash(f'Wybrano zawody: {zawody.nazwa}', 'success')
            return redirect(url_for('index'))  # Przekierowujemy, żeby zaktualizować sesję
        else:
            #Jeśli nie ma zawodów o tej nazwie to tworzymy nowe
            nowe_zawody = Zawody(nazwa=form.nazwa.data)
            db.session.add(nowe_zawody)
            db.session.commit()
            session['current_zawody_id'] = nowe_zawody.id  # Ustawiamy ID nowych zawodów w sesji
            session['current_zawody_nazwa'] = nowe_zawody.nazwa
            flash(f'Utworzono nowe zawody: {nowe_zawody.nazwa}', 'success')
            return redirect(url_for('index'))

    #Pobieramy informację o aktualnie trwających zawodach
    if 'current_zawody_id' in session:
        zawody = Zawody.query.get(session['current_zawody_id'])
    else:
        zawody = None  # Brak aktywnych zawodów
    return render_template('zawody.html', form=form, zawody=zawody)

@app.route('/zawody/usun', methods=['POST'])
@login_required
@role_required('admin')
def usun_zawody():
    if 'current_zawody_id' in session:
        zawody_id = session['current_zawody_id']
        zawody = Zawody.query.get_or_404(zawody_id)

        if zawody:
            # Usuń powiązane dane (kaskadowo)
            UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).delete()
            WynikLosowania.query.filter_by(zawody_id=zawody_id).delete()
            Zawodnik.query.filter_by(zawody_id=zawody_id).delete()
            db.session.delete(zawody)
            db.session.commit()
            flash(f'Zawody "{zawody.nazwa}" zostały usunięte!', 'success')
            session.pop('current_zawody_id', None)  # Usuń z sesji
            session.pop('current_zawody_nazwa', None)
        else:
            flash('Nie znaleziono zawodów do usunięcia.', 'error')
    else:
        flash('Najpierw wybierz zawody!', 'error')

    return redirect(url_for('zawody'))


@app.route('/ustawienia', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def ustawienia():
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    form = UstawieniaZawodowForm()
    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=session['current_zawody_id']).first()

    if form.validate_on_submit():
        if ustawienia:
            ustawienia.preferowana_liczba_stref = form.preferowana_liczba_stref.data
            ustawienia.preferowana_liczba_sektorow = form.preferowana_liczba_sektorow.data
            ustawienia.maks_liczba_stanowisk_w_sektorze = form.maks_liczba_stanowisk_w_sektorze.data
            ustawienia.liczba_tur = form.liczba_tur.data
        else:
            ustawienia = UstawieniaZawodow(
                preferowana_liczba_stref=form.preferowana_liczba_stref.data,
                preferowana_liczba_sektorow=form.preferowana_liczba_sektorow.data,
                maks_liczba_stanowisk_w_sektorze=form.maks_liczba_stanowisk_w_sektorze.data,
                liczba_tur=form.liczba_tur.data,
                zawody_id=session['current_zawody_id']  # Przypisujemy zawody_id
            )
            db.session.add(ustawienia)
        db.session.commit()
        flash('Ustawienia zapisane!', 'success')
        return redirect(url_for('ustawienia'))

    if ustawienia:
        form.preferowana_liczba_stref.data = ustawienia.preferowana_liczba_stref
        form.preferowana_liczba_sektorow.data = ustawienia.preferowana_liczba_sektorow
        form.maks_liczba_stanowisk_w_sektorze.data = ustawienia.maks_liczba_stanowisk_w_sektorze
        form.liczba_tur.data = ustawienia.liczba_tur

    return render_template('ustawienia.html', form=form, max_zawodnikow = UstawieniaZawodow.MAX_ZAWODNIKOW)

@app.route('/zawody/<int:zawody_id>')
@login_required
# @role_required('admin')  # Zdecyduj
def szczegoly_zawodow(zawody_id):
    zawody = Zawody.query.get_or_404(zawody_id)
    #Poprawne pobieranie danych
    zawodnicy = Zawodnik.query.filter_by(zawody_id=zawody_id).all()
    wyniki = WynikLosowania.query.filter_by(zawody_id=zawody_id).all()
    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=zawody_id).first()

    return render_template('szczegoly_zawodow.html', zawody=zawody, zawodnicy=zawodnicy, wyniki=wyniki, ustawienia=ustawienia)

#Widok do wprowadzania wyników
@app.route('/wprowadz_wyniki', methods=['GET', 'POST'])
@login_required
# @role_required('wagowy')  # Zdecyduj, czy tylko wagowy, czy admin też może wprowadzać wyniki
def wprowadz_wyniki():
    if 'current_zawody_id' not in session:
        flash('Najpierw wybierz zawody!', 'error')
        return redirect(url_for('zawody'))

    ustawienia = UstawieniaZawodow.query.filter_by(zawody_id=session['current_zawody_id']).first()
    if not ustawienia:
        flash("Najpierw ustaw parametry zawodów!", "error")
        return redirect(url_for("ustawienia"))

    # Formularz wyświetlamy tylko dla wybranej tury
    # Z formularza pobierzemy nr tury:
    wybrana_tura = request.form.get('tura', type=int)  # Pobieramy z formularza, domyślnie None
    #Jeżeli nie ma wybranej tury, to przekierowujemy do wyboru tury.
    if not wybrana_tura:
        return render_template('wybierz_ture.html', liczba_tur=ustawienia.liczba_tur)
     #Sprawdzamy czy w bazie są już jakieś wyniki dla tury.
    wyniki_tura = Wynik.query.filter_by(zawody_id=session['current_zawody_id'], tura=wybrana_tura).first()
    # Jeżeli nie ma wyników to nie ma sensu wyświetlać formularza.
    if not wyniki_tura:
        flash (f"Najpierw przeprowadź losowanie dla tury {wybrana_tura}", "error")
        return redirect(url_for('losowanie'))

    # Pobierz wyniki losowania i zawodników dla *aktualnych* zawodów
    wyniki_losowania = WynikLosowania.query.filter_by(zawody_id=session['current_zawody_id']).all()
    zawodnicy = Zawodnik.query.filter_by(zawody_id=session['current_zawody_id']).all()

    # Tworzymy formularz *dynamicznie*
    class DynamicWynikForm(WynikForm):
        pass

    for zawodnik in zawodnicy:
      # Dla każdego zawodnika dodajemy pola do formularza
      # Używamy formatowania, aby uzyskać unikalne nazwy pól, np. 'zawodnik_1_waga', 'zawodnik_1_bigfish'
      setattr(DynamicWynikForm, f'zawodnik_{zawodnik.id}_tura{wybrana_tura}_waga', FloatField(f'Waga (Zawodnik {zawodnik.imie_nazwisko or "Puste miejsce"}, Tura {wybrana_tura})', validators=[Optional()]))
      setattr(DynamicWynikForm, f'zawodnik_{zawodnik.id}_tura{wybrana_tura}_bigfish', FloatField(f'Big Fish (Zawodnik {zawodnik.imie_nazwisko or "Puste miejsce"}, Tura {wybrana_tura})', validators=[Optional()]))

    form = DynamicWynikForm(request.form)

    if request.method == 'POST' and form.validate_on_submit():
        # Zapisywanie wyników
      for wynik_losowania in wyniki_losowania:
        # Pobieramy zawodnika, dla którego to są wyniki:
        zawodnik = wynik_losowania.zawodnik

        # Pobieramy wprowadzone wartości z formularza (używając nazw pól, które wygenerowaliśmy dynamicznie)
        waga = getattr(form, f'zawodnik_{zawodnik.id}_tura{wybrana_tura}_waga').data
        bigfish = getattr(form, f'zawodnik_{zawodnik.id}_tura{wybrana_tura}_bigfish').data

        # Tworzymy nowy obiekt Wynik (lub aktualizujemy, jeśli już istnieje)
        wynik = Wynik.query.filter_by(zawodnik_id=zawodnik.id, zawody_id=session['current_zawody_id'], tura=wybrana_tura).first()
        if not wynik:
            wynik = Wynik(zawodnik_id=zawodnik.id, zawody_id=session['current_zawody_id'], tura=wybrana_tura)
            db.session.add(wynik)

        wynik.waga = waga if waga is not None else 0  # Ustawiamy na 0, jeśli puste
        wynik.bigfish = bigfish if bigfish is not None else 0
      db.session.commit()
      flash(f'Wyniki dla tury {wybrana_tura} zapisane!', 'success')
      return redirect(url_for('wyniki_losowania')) #lub tam gdzie chcesz

    return render_template('wprowadz_wyniki.html', form=form, wyniki_losowania=wyniki_losowania, tura=wybrana_tura, ustawienia=ustawienia)