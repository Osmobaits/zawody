from app import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='wagowy')

    def __repr__(self):
        return f'<User {self.username}, role: {self.role}>'

class Zawody(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nazwa = db.Column(db.String(200), nullable=False, unique=True)
    zawodnicy = db.relationship('Zawodnik', backref='zawody', lazy=True)
    wyniki_losowania = db.relationship('WynikLosowania', backref='zawody', lazy=True)
    ustawienia = db.relationship('UstawieniaZawodow', backref='zawody', lazy=True, uselist=False)


    def __repr__(self):
        return f'<Zawody {self.nazwa}>'

class Zawodnik(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    imie_nazwisko = db.Column(db.String(100), nullable=True) # Teraz może być Null, bo puste miejsce nie ma imienia
    zawody_id = db.Column(db.Integer, db.ForeignKey('zawody.id'), nullable=False)
    is_puste_miejsce = db.Column(db.Boolean, default=False) # Dodajemy nowe pole

    def __repr__(self):
        return f'<Zawodnik {self.imie_nazwisko}>'

class WynikLosowania(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    zawodnik_id = db.Column(db.Integer, db.ForeignKey('zawodnik.id'), nullable=False) #Teraz nie może być null
    zawodnik = db.relationship('Zawodnik', backref=db.backref('wyniki_losowania', lazy=True, cascade="all, delete-orphan"))
    zawody_id = db.Column(db.Integer, db.ForeignKey('zawody.id'), nullable=False)
    tura1_strefa = db.Column(db.String(1))
    tura1_sektor = db.Column(db.String(1))
    tura1_stanowisko = db.Column(db.Integer)
    tura2_strefa = db.Column(db.String(1))
    tura2_sektor = db.Column(db.String(1))
    tura2_stanowisko = db.Column(db.Integer)
    tura3_strefa = db.Column(db.String(1))
    tura3_sektor = db.Column(db.String(1))
    tura3_stanowisko = db.Column(db.Integer)
    tura4_strefa = db.Column(db.String(1))
    tura4_sektor = db.Column(db.String(1))
    tura4_stanowisko = db.Column(db.Integer)


    def __repr__(self):
        return f'<WynikLosowania dla zawodnika {self.zawodnik_id}>'

class UstawieniaZawodow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    preferowana_liczba_stref = db.Column(db.Integer, nullable=False, default=3)
    preferowana_liczba_sektorow = db.Column(db.Integer, nullable=False, default=2)
    maks_liczba_stanowisk_w_sektorze = db.Column(db.Integer, nullable=False, default=6)
    liczba_tur = db.Column(db.Integer, nullable=False, default=4)
    zawody_id = db.Column(db.Integer, db.ForeignKey('zawody.id'), nullable=False)


    MAX_ZAWODNIKOW = 120
    MAX_STREF = 4
    MAX_SEKTOROW = 12
    MAX_STANOWISK = 12
    MAX_TUR = 4

    def __repr__(self):
        return f'<UstawieniaZawodow>'
        
class Wynik(db.Model): #Nowy model
    id = db.Column(db.Integer, primary_key=True)
    zawodnik_id = db.Column(db.Integer, db.ForeignKey('zawodnik.id'), nullable=False)
    zawodnik = db.relationship('Zawodnik', backref=db.backref('wyniki', lazy=True))
    zawody_id = db.Column(db.Integer, db.ForeignKey('zawody.id'), nullable=False)
    tura = db.Column(db.Integer, nullable=False)
    waga = db.Column(db.Integer, nullable=False, default=0)  # Gramy, liczba całkowita
    bigfish = db.Column(db.Integer, nullable=False, default=0)  # Gramy, liczba całkowita

    def __repr__(self):
        return f'<Wynik zawodnika {self.zawodnik_id} w turze {self.tura}>'