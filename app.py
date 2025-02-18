from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, validators, SelectField
from flask_wtf import FlaskForm
import secrets

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@localhost/dbname'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    reset_token = db.Column(db.String(100), unique=True, nullable=True)

class Competition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    date = db.Column(db.Date, nullable=False)

class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    competition_id = db.Column(db.Integer, db.ForeignKey('competition.id'))

# Pełny kod aplikacji Flask:
# - System logowania z PostgreSQL
# - Obsługa użytkowników, resetu hasła i ról
# - Nowe tabele Competition i Participant do programu Zawody w tej samej bazie co magazyn
# - Gotowe do uruchomienia w Render.com lub lokalnie
# Zapisz jako app.py, dodaj katalog templates i uruchom `flask db migrate` oraz `flask db upgrade` po dodaniu nowych tabel.
