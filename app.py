from flask import Flask, render_template, url_for, redirect, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, DateField
from wtforms.validators import Optional, InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# Database URI (SQLite in this case)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secret key for form security (use a strong key in production)
app.config['SECRET_KEY'] = 'thisisasecretkey'

# Initialize login manager and bcrypt
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # This will be used when accessing protected routes

# Initialize database
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Define User model (SQLAlchemy)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


# Define Profile model (SQLAlchemy)
class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    Adhar = db.Column(db.BigInteger, nullable=True)
    DOB = db.Column(db.Date, nullable=True)
    address = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('profile', uselist=False))


# WindSpeedData model to store wind speed data
class WindSpeedData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    wind_speed = db.Column(db.Float, nullable=False)
    date = db.Column(db.String(10), nullable=False)  # Format: YYYYMMDD

    def __repr__(self):
        return f'<WindSpeedData {self.latitude}, {self.longitude}, {self.wind_speed}>'


# Registration form (WTForms)
class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different name.")


# Login form (WTForms)
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


# Routes
@app.route('/save_wind_speed', methods=['POST'])
def save_wind_speed():
    data = request.get_json()  # Get the JSON data sent from the frontend
    latitude = data['latitude']
    longitude = data['longitude']
    wind_speed = data['wind_speed']
    date = data['date']

    # Create a new WindSpeedData record
    new_data = WindSpeedData(
        latitude=latitude,
        longitude=longitude,
        wind_speed=wind_speed,
        date=date
    )

    try:
        # Add and commit the new record to the database
        db.session.add(new_data)
        db.session.commit()
        return jsonify({'message': 'Data saved successfully!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error saving data', 'error': str(e)}), 500


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')


@app.route('/windspeed', methods=['GET', 'POST'])
def windspeed():
    return render_template('indexw.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            flash("Login successful!", "success")
            login_user(user)
            return redirect(url_for('app2'))
        else:
            flash("Invalid username or password. Please try again.", "danger")
    return render_template('login.html', form=form)


# Run the app
if __name__ == '__main__':
    app.run(debug=True)
