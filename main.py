from flask import Flask, render_template, redirect, request, send_from_directory, url_for, flash, session, send_file, jsonify
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
from cryptidy import asymmetric_encryption
import hashlib
import json
import blockchain
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

blockchain = blockchain.Blockchain()


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


@app.route('/get_chain', methods=['GET'])
def display_chain():
    response = {'chain': blockchain.chain, 'length': len(blockchain.chain)}
    return render_template('blockchain.html', chain=response)


@app.route('/valid', methods=['GET'])
def valid():
    is_valid = blockchain.chain_valid(blockchain.chain)
    message = 'The Blockchain is valid.' if is_valid else 'The Blockchain is not valid.'
    return render_template('valid.html', message=message)


@app.route('/generate', methods=['GET', 'POST'])
def key_generate():
    if request.method == 'POST':
        # Get the selection from the form
        folder = request.form['key_option']

        # Generate the keys
        priv_key, pub_key = asymmetric_encryption.generate_keys(2048)  # 2048 bits RSA key

        if folder == 'u':
            with open('user/pub/pub_key.key', "wb") as key_file:
                key_file.write(pub_key.encode(encoding="utf-8"))
            with open('admin/priv/pri_key.key', "wb") as key_file:
                key_file.write(priv_key.encode(encoding="utf-8"))
            return 'Public Key uploaded and Private Key generated successfully!'

        elif folder == 'd':
            with open('admin/pub/pub_key.key', "wb") as key_file:
                key_file.write(pub_key.encode(encoding="utf-8"))
            with open('user/priv/pri_key.key', "wb") as key_file:
                key_file.write(priv_key.encode(encoding="utf-8"))
            return 'Private Key uploaded and Public Key generated successfully!'

    return render_template('generate.html')


@app.route('/download', methods=['GET', 'POST'])
def download():
    if request.method == 'POST':
        encrypted = request.form['filename']
        print(encrypted)
        try:
            enc_file = open(encrypted, "rb").read()
            priv_key = open('admin/priv/pri_key.key', "rb").read()

            # Decrypt the file content7
            timestamp, original_object = asymmetric_encryption.decrypt_message(enc_file, priv_key.decode())

            # Save decrypted content to a temporary file
            with open(encrypted, "w") as output_file:
                output_file.write(str(original_object))

            # Send the decrypted file as an attachment
            return send_file(encrypted, as_attachment=True)

        except FileNotFoundError:
            return f"Error: File '{encrypted}' not found.", 404

        except Exception as e:
            return f"An error occurred: {str(e)}", 500

    # Render the form for filename input
    return render_template('download.html')


@app.route('/add', methods=['GET', 'POST'])  # this is like a secret route where u have type manually to add
def add_cafe():
    if request.method == "POST":
        pub_key = open('user/pub/pub_key.key', "rb").read()

        # Handle uploaded file
        uploaded_file = request.files['file']
        new_filename = request.form['filename']

        if uploaded_file.filename and new_filename:
            uploaded_file.save(uploaded_file.filename)

            # Encrypt the file content
            with open(uploaded_file.filename, 'r') as file:
                file_content = file.read()

            encrypted = asymmetric_encryption.encrypt_message(file_content, pub_key.decode())

            # Save encrypted content to the new file
            with open(f"{new_filename}.enc", "wb") as text_file:
                text_file.write(encrypted)

            os.remove(uploaded_file.filename)  # Clean up original file

            # Add block to the blockchain
            previous_block = blockchain.print_previous_block()
            previous_proof = previous_block['proof']
            proof = blockchain.proof_of_work(previous_proof)
            previous_hash = blockchain.hash(previous_block)
            block = blockchain.create_block(proof, previous_hash, f"File {new_filename}.enc encrypted.")

            response = {
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
                'message': block['message']}
            return render_template('response.html', response=response)

        #return redirect("cafes")  # redirect back to /cafes after 10 seconds
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
        uploaded_file = form.file.data
        if uploaded_file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(file_path)

            flash("File uploaded successfully! Your account has been registered.")
            return redirect(url_for('login'))

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


# FOR REGISTER, button for generating key,


if __name__ == '__main__':
    app.run(port=5001, debug=True)
