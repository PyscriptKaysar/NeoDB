import random
import string
from io import BytesIO
from pathlib import Path

from flask import Flask, render_template, redirect, request, send_from_directory, url_for, flash, session, send_file, \
    jsonify, make_response
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


class FileMetadata(db.Model):
    __tablename__ = "file_metadata"
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(250), nullable=False)
    uploader = db.Column(db.String(250), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)


7
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
    return jsonify(response)


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
        encrypted_file = request.form['filename']
        try:
            # Read the encrypted file
            enc_file_content = open(f'uploads/{encrypted_file}', "rb").read()

            # Read the private key
            priv_key = open('admin/priv/pri_key.key', "rb").read()

            # Decrypt the file content
            timestamp, original_object = asymmetric_encryption.decrypt_message(enc_file_content, priv_key.decode())

            # Save the decrypted content to a temporary file
            decrypted_file_path = f"{encrypted_file}.decrypted"
            with open(decrypted_file_path, "w") as output_file:
                output_file.write(str(original_object))

            # Send the decrypted file as a download
            return send_file(decrypted_file_path, as_attachment=True)

        except FileNotFoundError:
            return f"Error: File '{encrypted_file}' not found.", 404

        except Exception as e:
            return f"An error occurred: {str(e)}", 500

        # Render the form for filename input
    return render_template('download.html')


add_data = []


@app.route('/add', methods=['GET', 'POST'])
def add_cafe():
    if request.method == "POST":
        pub_key = open('user/pub/pub_key.key', "rb").read()

        # Handle uploaded file
        uploaded_file = request.files.get('file')
        new_filename = request.form.get('filename')
        uploader = request.form.get('uploader', 'Anonymous')  # Default to 'Anonymous' if not provided

        if uploaded_file and uploaded_file.filename and new_filename:
            # Save the uploaded file
            uploaded_file.save(uploaded_file.filename)

            # Encrypt the file content
            with open(uploaded_file.filename, 'r') as file:
                file_content = file.read()

            encrypted = asymmetric_encryption.encrypt_message(file_content, pub_key.decode())

            # Save encrypted content to the new file
            encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{new_filename}.enc")
            with open(encrypted_file_path, "wb") as text_file:
                text_file.write(encrypted)

            # Get file metadata
            file_size = os.path.getsize(encrypted_file_path)

            """
            # Save metadata to the database
            new_file = FileMetadata(
                file_name=new_filename,
                uploader=uploader,
                file_type=file_type,
                file_size=file_size
            )
            db.session.add(new_file)
            db.session.commit()
            """

            os.remove(uploaded_file.filename)  # Clean up original file

            # Add block to the blockchain
            previous_block = blockchain.print_previous_block()
            previous_proof = previous_block['proof']
            proof = blockchain.proof_of_work(previous_proof)
            previous_hash = blockchain.hash(previous_block)
            block = blockchain.create_block(proof, previous_hash)

            add_data.append({
                "Index": block['index'],
                "File Name": new_filename,
                "Uploaded By": uploader,
                "File Size (Bytes)": file_size,
                "View File": url_for('view_file', filename=new_filename),
                "Previous Hash": block['previous_hash'],
                "Proof": block['proof'],
                "Timestamp": block['timestamp']
            })

            response = {
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'], }

            return render_template('response.html', response=response)

    return render_template('add.html')


@app.route('/cafes')
def cafes():
    return render_template('cafes.html', files=add_data)


@app.route('/view/<filename>')
def view_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
    if os.path.exists(file_path):
        # Read the encrypted file content
        with open(file_path, 'rb') as enc_file:
            encrypted_content = enc_file.read()

        # Render the encrypted content as plain text inside the browser
        return render_template('view_file.html', content=encrypted_content.decode('utf-8', errors='ignore'))
    else:
        return "File not found.", 404


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        e_id = request.form.get('e_id')  # Correctly access 'e_id' from the form

        if os.path.exists(f'admin/pub/{e_id}.key'):
            return render_template('register.html', error="User already exists.")

        priv_key, pub_key = asymmetric_encryption.generate_keys(2048)
        with open(f'admin/pub/{e_id}.key', "wb") as key_file:
            key_file.write(pub_key.encode(encoding="utf-8"))
        # Create an in-memory file
        priv_key_stream = BytesIO()
        priv_key_stream.write(priv_key.encode("utf-8"))
        priv_key_stream.seek(0)  # Move to the beginning of the stream

        # Send the file to the user's computer without saving it to disk
        return send_file(
            priv_key_stream,
            as_attachment=True,
            download_name=f"{e_id}.key"
        )

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    session_id = request.cookies.get('user_id')
    if session_id:
        return f"Logged in as {session_id}"

    if request.method == 'POST':
        id = request.form['id']
        key = request.files['key']
        key.save(key.filename)
        j = f'admin/pub/{id}.key'
        res = ''.join(random.choices(string.ascii_letters, k=7))
        with open(key.filename, 'rb') as f:
            pri = f.read()
        with open(j, 'rb') as f:
            pub = f.read()
        auth = asymmetric_encryption.encrypt_message(res, pub.decode())
        timestamp, c_auth = asymmetric_encryption.decrypt_message(auth, pri.decode())

        resp = make_response("Logged in successfully")
        resp.set_cookie('user_id', id, max_age=3600)  # The cookie will expire in 1 hour

        return resp

    return render_template('login2.html')


@app.route('/logout')
def logout():
    resp = make_response("Logged out successfully")
    resp.delete_cookie('user_id')  # Delete the user_id cookie
    return resp


# FOR REGISTER, button for generating key,


if __name__ == '__main__':
    app.run(port=5001, debug=True)
