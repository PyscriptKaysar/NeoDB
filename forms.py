from flask_wtf import FlaskForm  # pip install Flask-WTF
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL


# TODO: Create a RegisterForm to register new users
# Creating a form for creating new posts
class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(message=None)])
    password = StringField('Password', validators=[DataRequired(message=None)])
    name = StringField('Name', validators=[DataRequired(message=None)])
    submit = SubmitField('SIGN ME UP!')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(message=None)])
    password = StringField('Password', validators=[DataRequired(message=None)])
    submit = SubmitField('LET ME IN!')


