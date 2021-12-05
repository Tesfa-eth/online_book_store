from enum import unique
from flask import Flask, app, render_template, url_for, redirect
import flask
from flask.helpers import flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_manager, login_user, LoginManager, login_required,logout_user, current_user
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
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

global_username = ''

@login_manager.user_loader
def load_user(user_id):
    """load user"""
    return User.query.get(int(user_id))


class User(db.Model, UserMixin): # creating the table
    """User table with user name and hashed password colums"""
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(20), nullable=True, unique=False)
    lastname = db.Column(db.String(20), nullable=True, unique=False)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    firstname = StringField(validators=[InputRequired(), Length(min=4,max=20)],
    render_kw={"placeholder": "First name"})

    lastname = StringField(validators=[InputRequired(), Length(min=4,max=20)],
    render_kw={"placeholder": "Last name"})

    username = StringField(validators=[InputRequired(), Length(min=4,max=20)],
    render_kw={"placeholder": "Enter username/email here"})

    password = PasswordField(validators=[InputRequired(), Length(min=4,max=20)],
    render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        #Checks if there is the username already exists
        existing_username = User.query.filter_by(username=username.data).first()
        if existing_username:
            #print('existing user name') #debug
            # redirect somewhere after this!
            raise ValidationError(
                "The username already exists. Please choose a different one."
            )
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=20)],
    render_kw={"placeholder": "Username/email"})

    password = PasswordField(validators=[InputRequired(), Length(min=4,max=20)],
    render_kw={"placeholder": "Password"})

    submit = SubmitField("Log in")

@app.route('/')
def index():
    """render index html"""
    print(current_user.is_authenticated)
    return render_template('index.html', auth=current_user.is_authenticated)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """register a newuser"""
    form = RegisterForm()
    if form.validate_on_submit():
        print("validating")
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        # get the form
        print('creating table')
        new_user = User(firstname=form.firstname.data, lastname=form.lastname.data,username=form.username.data, password=hashed_password)
        db.create_all() # create the table
        db.session.add(new_user)
        db.session.commit()
        print('table created')
        #print(new_user.query.all()) -- debug
        #print(User.query.filter_by(username = 'test1').all())
        flash('Successfully Registered!')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    #print(current_user.is_authenticated) # check if user logged in
    global global_username
    global global_user_id
    form = LoginForm()
    #print("username -",form.username.data, "password- ", form.password.data) # debug
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            global_username = user.username # make these two global for future queries
            global_user_id = user.id
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                #flash(f'Welcome, {user.username}')
                return redirect(url_for('dashboard'))
            else:
                flash(f'Wrong password!')
        else:
            flash(f'Wrong username')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    """log out the user"""
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard',methods=['GET', 'POST'])
@login_required
def dashboard():
    # object username
    #print(load_user(user_id_print).username) -- gives me the id and username of logged person
    #market = SampleMarket.query.all()
    user = User.query.filter_by(id=global_user_id).first()
    flash(f'Welcome back {user.firstname} {user.lastname}!!!')
    #print(user.firstname)
    return render_template('dashboard.html', username=global_username)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)