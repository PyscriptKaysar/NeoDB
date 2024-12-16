
import random
import string
from io import BytesIO
from flask import Flask, render_template, redirect, request, url_for, session, send_file, make_response
from flask_bootstrap import Bootstrap5  # pip install bootstrap-flask
from flask_login import login_required
from datetime import timedelta  # timer for logging out the user
from cryptidy import asymmetric_encryption
import blockchain
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_bootstrap import Bootstrap5
import random
import string
import os
from cryptidy import asymmetric_encryption
import json

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)

base_path = os.path.abspath(os.path.dirname(__file__))

# Define the upload folder path, you can adjust this as needed
UPLOAD_FOLDER = os.path.join((base_path), 'uploads')

# Configure the app to use this folder for file uploads
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Initialize Bootstrap
Bootstrap5(app)

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

# Blockchain object
blockchain = blockchain.Blockchain()

# User data structure (simulating a user database for now)
users = {}

# Custom User class to integrate with Flask-Login
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        e_id = request.form.get('e_id')
        pub_dir = os.path.join(base_path, 'admin', 'pub')

        # Ensure the directory exists
        if not os.path.exists(pub_dir):
            os.makedirs(pub_dir, exist_ok=True)

        file_path = os.path.join(pub_dir, f'{e_id}.key')

        if os.path.exists(file_path):
            return render_template('register.html', error="User already exists.")

        priv_key, pub_key = asymmetric_encryption.generate_keys(2048)

        # Save public key
        with open(file_path, "wb") as key_file:
            key_file.write(pub_key.encode(encoding="utf-8"))

        # Send private key as a downloadable file
        priv_key_stream = BytesIO()
        priv_key_stream.write(priv_key.encode("utf-8"))
        priv_key_stream.seek(0)

        return send_file(priv_key_stream, as_attachment=True, download_name=f"{e_id}.key")

    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            user_id = request.form['id']
            key = request.files['key']
            key.save(key.filename)

    # Get the absolute path to the current directory
            pub_key_path = os.path.join(base_path, 'admin', 'pub', f'{user_id}.key')
            with open(key.filename, 'rb') as f:
                pri_key = f.read()

            with open(pub_key_path, 'rb') as j:
                pub_key = j.read()

            res = ''.join(random.choices(string.ascii_letters, k=7))
            auth = asymmetric_encryption.encrypt_message(res, pub_key.decode())
            timestamp, c_auth = asymmetric_encryption.decrypt_message(auth, pri_key.decode())

            # Simulate user login
            if c_auth == res:
                users[user_id] = User(user_id)
            
            login_user(users[user_id])  # Log the user in with Flask-Login

            resp = make_response(redirect(url_for('cafes')))
            resp.set_cookie('user_id', user_id, max_age=36000)

            return resp
    except ValueError:
        return "Wrong user ID or Private key provided"
    return render_template('login2.html')

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Log the user out with Flask-Login
    resp = make_response("Logged out successfully")
    resp.delete_cookie('user_id')  # Delete the user_id cookie
    return resp

# Home Route
@app.route("/")
def home():
    user_id = session.get('user_id')
    if user_id:
        return render_template("index.html", user_id=user_id)
    else:
        return render_template("index.html")

# Protected Route (Requires login)
@app.route('/admin')
@login_required
def protected():
    return render_template('admin.html')

# Other routes (keeping your original routes intact)
@app.route('/generate', methods=['GET', 'POST'])
@login_required
def key_generate():
    if request.method == 'POST':
        folder = request.form['key_option']
        u_id = request.cookies.get('user_id')
        # Generate keys
        priv_key, pub_key = asymmetric_encryption.generate_keys(2048)
        
        # Get the absolute path to the desired directories
        admin_pub_dir = os.path.join(base_path, 'admin', 'pub')
        admin_priv_dir = os.path.join(base_path, 'admin', 'priv')

        # Ensure the directories exist, if not create them
        os.makedirs(admin_pub_dir, exist_ok=True)
        os.makedirs(admin_priv_dir, exist_ok=True)

        # Handle the file saving and sending based on the folder option
        if folder == 'u':
            # Send the public key to the user for download
            pub_path = os.path.join(admin_pub_dir, f"{u_id}_pub.key")
            with open(pub_path, "wb") as pub_key_file:
                pub_key_file.write(pub_key.encode("utf-8"))

            priv_path = os.path.join(admin_priv_dir, f"{u_id}_priv.key")
            # Save the private key in the admin's private directory
            with open(priv_path, "wb") as key_file:
                key_file.write(priv_key.encode("utf-8"))

            # Send the public key as a downloadable file
            return send_file(
                pub_path,
                as_attachment=True,
                download_name="pub_key.key"
            )

        elif folder == 'd':

            # Send the private key as a downloadable file
            return send_file(
                os.path.join(admin_priv_dir, f"{u_id}_priv.key"),
                as_attachment=True,
                download_name="pri_key.key"
            )

    return render_template('generate.html')

@app.route('/chain')
@login_required
def cafes():
    return render_template('cafes.html', files=add_data)

add_data = []

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_cafe():
    if request.method == "POST":
        # Get the uploaded public key file
        pub_key_file = request.files.get('pub_key')

        if pub_key_file:
            # Read the public key from the uploaded file
            pub_key = pub_key_file.read().decode("utf-8")
        else:
            return "Public key is required!"

        uploaded_file = request.files.get('file')
        new_filename = request.form.get('filename')
        uploader = request.form.get('uploader', 'Anonymous')

        if uploaded_file and uploaded_file.filename and new_filename:
            # Save the uploaded file temporarily
            uploaded_file.save(uploaded_file.filename)

            # Encrypt the file content
            with open(uploaded_file.filename, 'rb') as file:
                file_content = file.read()

            encrypted = asymmetric_encryption.encrypt_message(file_content, pub_key)

            encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{new_filename}")
            with open(encrypted_file_path, "wb") as text_file:
                text_file.write(encrypted)

            file_size = os.path.getsize(encrypted_file_path)
            os.remove(uploaded_file.filename)

            previous_block = blockchain.print_previous_block()
            previous_proof = previous_block['proof']
            proof = blockchain.proof_of_work(previous_proof)
            previous_hash = blockchain.hash(previous_block)
            block = blockchain.create_block(proof, previous_hash)

            logs_file_path = os.path.join(base_path, 'logs.json')
            new_data = {
                "Index": block['index'],
                "File Name": new_filename,
                "Uploaded By": uploader,
                "File Size (Bytes)": file_size,
                "View File": url_for('view_file', filename=new_filename),
                "Previous Hash": block['previous_hash'],
                "Proof": block['proof'],
                "Timestamp": block['timestamp']
            }

            # Step 1: Load existing data from the file, if it exists
            if os.path.exists(logs_file_path):
                with open(logs_file_path, 'r') as json_file:
                    try:
                        # Load existing data into add_data
                        existing_data = json.load(json_file)
                        add_data.extend(existing_data)  # Append existing data to the add_data list
                    except json.JSONDecodeError:
                        # If the file is empty or corrupt, do nothing, just continue with empty add_data
                        pass

            # Step 2: Append new data to add_data list
            add_data.append(new_data)

            # Step 3: Save the updated add_data back to the file
            with open(logs_file_path, 'w') as json_file:
                json.dump(add_data, json_file, indent=4)

            response = {
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
            }

            return render_template('response.html', response=response)

    return render_template('add.html')

@app.route('/view/<filename>')
@login_required
def view_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as enc_file:
            encrypted_content = enc_file.read()

        return render_template('view_file.html', content=encrypted_content.decode('utf-8', errors='ignore'))
    else:
        return "File not found.", 404

@app.route('/download', methods=['GET', 'POST'])    
@login_required
def download():
    if request.method == 'POST':
        encrypted_file = request.form['filename']
        priv_key_file = request.files.get('priv_key')
        u_id = request.cookies.get('user_id')
        try:
            # Get the path to the encrypted file
            e_file = os.path.join(base_path, 'uploads', encrypted_file)
            print(f"Encrypted file path: {e_file}")
            
            # Read the encrypted file content
            with open(e_file, "rb") as file:
                enc_file_content = file.read()
            print(f"Encrypted file content: {enc_file_content}")

            # Get the uploaded private key from the user
 
            # Read the private key content from the uploaded file

            if priv_key_file:
                priv_key_content = priv_key_file.read().decode("utf-8")
                print(f"Private key content: {priv_key_content}")
            else:
                return 'Private Key is required'
            # Decrypt the file content using the private key
            timestamp, original_object = asymmetric_encryption.decrypt_message(enc_file_content, priv_key_content)

            # Save the decrypted content to a temporary file
            d_file = os.path.join(base_path,encrypted_file)
            with open(d_file, "w") as output_file:
                output_file.write(str(original_object))

            # Send the decrypted file as a download
            return send_file(d_file, as_attachment=True)

        except FileNotFoundError:
            return f"Error: File '{encrypted_file}' not found.", 404
        # except Exception as e:
        #     return f"An error occurred: {str(e)}", 500

    # Render the form for filename input and private key upload
    return render_template('download.html')
# You can keep the rest of your routes here, ensuring any route requiring login has the `@login_required` decorator.

if __name__ == '__main__':
    app.run(port=5000, debug=True)
