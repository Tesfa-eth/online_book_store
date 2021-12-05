from enum import unique
from flask import Flask, app, render_template, url_for, redirect
import flask
from flask.helpers import flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_manager, login_user, LoginManager, login_required,logout_user
from flask_wtf.form import FlaskForm
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' # connects to the db
app.config['SECRET_KEY'] = 'thisisasecretekey'

# log in manager
"""login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view="login" """

class User(db.Model, UserMixin): # creating the table
    """User table with user name and hashed password colums"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=20)],
    render_kw={"placeholder": "Enter username here"})

    password = PasswordField(validators=[InputRequired(), Length(min=4,max=20)],
    render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    """def validate_username(self, username):
        #Checks if there is the username already exists
        # the error is here!
        existing_username = User.query.filter_by(username=username.data).first()
        if existing_username:
            #print('existing user name') #debug
            # redirect somewhere after this!
            raise ValidationError(
                "The username already exists. Please choose a different one."
            )"""

@app.route('/')
def index():
    """render index html"""
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """register a newuser"""
    form = RegisterForm()
    if form.validate_on_submit():
        print("validating")
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        # get the form
        new_user = User(username=form.username.data, password=hashed_password)
        db.create_all() # create the table
        db.session.add(new_user)
        db.session.commit()
        #print(new_user.query.all()) -- debug
        #print(User.query.filter_by(username = 'test1').all())
        flash('Successfully Registered!')
        #return redirect(url_for('login'))
    return render_template('signup.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)