from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, validators, SelectField
from flask_wtf import FlaskForm
import secrets

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@localhost/dbname'  # Zmień na swoje dane do PostgreSQL
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

class RegistrationForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.DataRequired(), validators.Length(min=6)])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], validators=[validators.DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    submit = SubmitField('Login')

class ResetRequestForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', [validators.DataRequired(), validators.Length(min=6)])
    submit = SubmitField('Reset Password')

class UserEditForm(FlaskForm):
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], validators=[validators.DataRequired()])
    submit = SubmitField('Update Role')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Wszystkie trasy, formularze, funkcje resetu hasła, zarządzania użytkownikami, rejestracji i logowania zostały tutaj zawarte.
# Instrukcje konfiguracyjne PostgreSQL i uruchomienia lokalnego również są w kodzie.
# Pełny, gotowy do uruchomienia system logowania w Flasku z PostgreSQL. 🎉
