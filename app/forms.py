from flask_wtf import FlaskForm # POPRAWKA: Upewnij się, że importujesz FlaskForm
# from wtforms import Form # POPRAWKA: Usunięto niepotrzebny import, jeśli WynikForm była jedyną używającą go
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, SelectField, FloatField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, NumberRange, Optional
from app.models import User, UstawieniaZawodow

class RegistrationForm(FlaskForm):
    username = StringField('Nazwa użytkownika', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Hasło', validators=[DataRequired()])
    confirm_password = PasswordField('Potwierdź hasło', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Rola', choices=[('admin', 'Admin'), ('wagowy', 'Wagowy')], validators=[DataRequired()])
    submit = SubmitField('Zarejestruj')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Ta nazwa użytkownika jest już zajęta. Wybierz inną.')

class LoginForm(FlaskForm):
    username = StringField('Nazwa użytkownika', validators=[DataRequired()])
    password = PasswordField('Hasło', validators=[DataRequired()])
    remember = BooleanField('Zapamiętaj mnie')
    submit = SubmitField('Zaloguj')

class ZawodnikForm(FlaskForm):
    imie_nazwisko = StringField('Imię i nazwisko', validators=[DataRequired()])
    submit = SubmitField('Zapisz')

class ZawodyForm(FlaskForm):
    nazwa = StringField('Nazwa zawodów', validators=[DataRequired()])
    submit = SubmitField('Zapisz')

class UstawieniaZawodowForm(FlaskForm):
     preferowana_liczba_stref = IntegerField(
        'Preferowana liczba stref',
        validators=[DataRequired(), NumberRange(min=1, max=UstawieniaZawodow.MAX_STREF)]
    )
     preferowana_liczba_sektorow = IntegerField(
        'Preferowana liczba sektorów w strefie',
        validators=[DataRequired(), NumberRange(min=1, max=UstawieniaZawodow.MAX_SEKTOROW)]
    )
     maks_liczba_stanowisk_w_sektorze = IntegerField(
        'Maksymalna liczba stanowisk w sektorze',
        validators=[DataRequired(), NumberRange(min=1, max=UstawieniaZawodow.MAX_STANOWISK)]
    )
     liczba_tur = IntegerField(
        'Liczba tur',
        validators=[DataRequired(), NumberRange(min=1, max=UstawieniaZawodow.MAX_TUR)]
    )
     submit = SubmitField('Zapisz ustawienia')

     def validate(self, extra_validators=None):
        # POPRAWKA: Użycie super() jest bardziej standardowe i elastyczne niż jawne podanie klasy bazowej
        initial_validation = super().validate(extra_validators=extra_validators)
        if not initial_validation:
            return False

        # Sprawdzanie czy dane liczbowe istnieją (walidatory mogły nie przepuścić)
        if self.preferowana_liczba_stref.data is None or \
           self.preferowana_liczba_sektorow.data is None or \
           self.maks_liczba_stanowisk_w_sektorze.data is None:
            return False # Już wystąpił błąd walidacji

        maks_zaw = (
            self.preferowana_liczba_stref.data
            * self.preferowana_liczba_sektorow.data
            * self.maks_liczba_stanowisk_w_sektorze.data
        )
        if maks_zaw > UstawieniaZawodow.MAX_ZAWODNIKOW:
            msg = (
                f'Maksymalna liczba zawodników ({UstawieniaZawodow.MAX_ZAWODNIKOW}) '
                f'zostałaby przekroczona przy tych ustawieniach (Aktualnie: {maks_zaw}). '
                f'Zmniejsz liczbę stref, sektorów lub stanowisk.'
            )
            # Dodawaj błędy do konkretnych pól, aby były widoczne przy nich
            self.preferowana_liczba_stref.errors.append(msg)
            # self.preferowana_liczba_sektorow.errors.append(msg) # Wystarczy przy jednym polu
            # self.maks_liczba_stanowisk_w_sektorze.errors.append(msg)
            return False

        return True

# POPRAWKA: Dziedziczenie z FlaskForm zamiast z Form
class WynikForm(FlaskForm):
    submit = SubmitField('Zapisz wyniki')
    # Pola dla wagi i bigfish będą dodawane dynamicznie w widoku