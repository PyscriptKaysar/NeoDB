from flask import Flask, render_template, redirect, request, send_from_directory, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm  # a module for easy validation , more security of forms, less code
from sqlalchemy import Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired, URL
from flask_bootstrap import Bootstrap5  # pip install bootstrap-flask
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from datetime import timedelta  # timer for logging out the user
import csv
import forms
import os

app = Flask(__name__)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)


# CREATE DATABASE

class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['UPLOAD_FOLDER'] = 'uploads'
Bootstrap5(app)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.execute(db.select(User).where(User.id == user_id)).scalar()


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)


with app.app_context():
    db.create_all()


# Ensure the upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


@app.route("/")
def home():
    return render_template("index.html")


@app.route('/add', methods=['GET', 'POST'])  # this is like a secret route where u have type manually to add
def add_cafe():
    if request.method == "POST":
        uploaded_file = request.files.get('file')
        if uploaded_file and uploaded_file.filename:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(file_path)
        return redirect("cafes")  # after submitting, it will redirect us to cafes page
    return render_template('add.html')


@app.route('/cafes')
def cafes():
    uploaded_files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('cafes.html', cafes=uploaded_files)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = forms.RegisterForm(meta={'csrf': True})
    if form.validate_on_submit():
        email = form.data['email']
        check_exist_user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if check_exist_user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")  # pops up the message
            return redirect(url_for('login'))

        password = generate_password_hash(form.data['password'], method='pbkdf2:sha256', salt_length=8)  # hashed and salted password
        add_user = User(email=form.data['email'], password=password, name=form.data['name'])  # the argument doesn't cause any error its fine
        db.session.add(add_user)
        db.session.commit()
        login_user(add_user)  # login and authenticate user after registering succesfully
        return redirect(url_for('cafes'))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = forms.LoginForm(meta={'csrf': True})
    if form.validate_on_submit():
        email = form.data['email']
        password = form.data['password']
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if not user:
            flash("That email does not exist, please try again.")  # pops up the message
            return redirect('/login')
        elif not check_password_hash(pwhash=user.password, password=password):  # decoding the password/ checking if it's the same
            flash('Password incorrect, please try again.')  # pops up the message
            return redirect('/login')
        else:
            login_user(user)  # logging in this user
            session.permanent = True  # Make the session respect PERMANENT_SESSION_LIFETIME
            return redirect(url_for('cafes'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(port=5001, debug=True)
