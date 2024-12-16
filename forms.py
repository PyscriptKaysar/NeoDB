from flask_wtf import FlaskForm  # pip install Flask-WTF
from wtforms import StringField, SubmitField, FileField
from wtforms.validators import DataRequired, URL


# TODO: Create a RegisterForm to register new users

class RegisterForm(FlaskForm):
    file = FileField('Biometric Scan', validators=[DataRequired(message="Please upload a file.")])
    submit = SubmitField('Generate Key')


class LoginForm(FlaskForm):
    file = FileField('Upload Access Key File', validators=[DataRequired(message="Please upload a file.")])
    submit = SubmitField('LET ME IN!')


