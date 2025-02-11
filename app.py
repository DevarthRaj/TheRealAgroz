from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField,DateField
from wtforms.validators import Optional
from wtforms.validators import InputRequired, Length, ValidationError
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


# The UpdateProfileForm class defines a form for updating the user's profile.
class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    adhar = StringField('Adhar', validators=[Optional()])
    
    # 'dob' field is used to input the date of birth. The format of the date is YYYY-MM-DD.
    dob = DateField('Date of Birth', format='%Y-%m-%d', validators=[Optional()])
    
    # 'address' field allows the user to input their address, which is an optional field.
    address = StringField('Address', validators=[Optional()])
    
    # 'submit' field is the submit button to submit the form.
    submit = SubmitField('Update Profile')


# Routes
@app.route('/app2', methods=['GET', 'POST'])
@login_required
def app2():
    return render_template('app2.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



@app.route('/updateprofile', methods=['GET', 'POST'])
@login_required
def update_profile():
    form = UpdateProfileForm()  # Create the form instance
    
    # Check if the form is submitted and validated
    if form.validate_on_submit():
        # Handle form data and update the user's profile here
        # For example, updating the profile information in the database
        current_user.profile.username = form.username.data
        current_user.profile.Adhar = form.adhar.data
        current_user.profile.DOB = form.dob.data
        current_user.profile.address = form.address.data
        
        db.session.commit()  # Save the changes to the database
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))  # Redirect to the profile page

    return render_template('updateprofile.html', form=form)  # Pass the form to the template



@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user  # Get the currently logged-in user
    profile = Profile.query.filter_by(username=user.username).first()  # Get the profile associated with the user
    
    form = UpdateProfileForm(obj=profile)  # Pre-populate form with the current profile data
    
    if form.validate_on_submit():
        profile.username = form.username.data
        profile.Adhar = form.adhar.data
        profile.DOB = form.dob.data
        profile.address = form.address.data
        
        db.session.commit()  # Save the changes to the database
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))  # Redirect to the profile page

    return render_template('profile.html', form=form, profile=profile)  # Pass both form and profile

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')


@app.route('/ricecrop', methods=['GET', 'POST'])
def crop():
    return render_template('indexc.html')


@app.route('/windspeed', methods=['GET', 'POST'])
def windspeed():
    return render_template('indexw.html')


@app.route('/resources', methods=['GET', 'POST'])
def resource():
    return render_template('resource.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    return render_template('contact.html')


# Login route
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


# Sign Up route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Create the profile after the user is created
        new_profile = Profile(username=form.username.data, user_id=new_user.id)
        db.session.add(new_profile)
        db.session.commit()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


# Run the app
if __name__ == '__main__':
    app.run(debug=True)

