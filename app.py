from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import random
import time
from datetime import timedelta
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp
from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)
app.secret_key = '8ab1d5c5b06706a607dbb9b6440c9667040303bcef9810925822247ad964ac35'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'haraiharan3112004@gmail.com'
app.config['MAIL_PASSWORD'] = 'vrvr iqhv bwyo dkky'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)  

mail = Mail(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(),Length(min=8),Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])', message="Password must contain upper, lower, number, and special char.")])
    captcha = StringField('What is 3 + 4?', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class OTPForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[DataRequired()])
    submit = SubmitField('Verify OTP')

@app.before_request
def before_request():
    
    if 'email' in session:
        session.modified = True  
        session.permanent = True  

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        captcha = form.captcha.data

        if captcha != '7':
            flash('CAPTCHA incorrect!', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered!')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        otp = random.randint(100000, 999999)
        session['temp_email'] = email
        session['temp_password'] = hashed_password
        session['otp'] = otp
        session['otp_time'] = int(time.time())
        session['wrong_attempts'] = 4

        msg = Message('Your OTP Code', sender='haraiharan3112004@gmail.com', recipients=[email])
        msg.body = f"Your OTP is {otp}. It expires in 5 minutes."
        mail.send(msg)

        flash('OTP sent to your email. Please verify.', 'info')
        return redirect(url_for('verify_otp'))

    return render_template('register.html', form=form)

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    form = OTPForm()

    if 'wrong_attempts' not in session:
        session['wrong_attempts'] = 4

    if form.validate_on_submit():
        entered_otp = form.otp.data
        saved_otp = session.get('otp')
        otp_time = session.get('otp_time')

        if otp_time and time.time() - otp_time > 300:
            flash('OTP expired! Resend OTP.')
            return redirect(url_for('resend_otp'))

        if str(saved_otp) == entered_otp:
            email = session.get('temp_email')
            password = session.get('temp_password')

            new_user = User(email=email, password=password)
            db.session.add(new_user)
            db.session.commit()

            session.clear()

            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        else:
            session['wrong_attempts'] += 1

            if session['wrong_attempts'] >= 3:
                session.clear()
                flash('Too many wrong OTP attempts. Registration locked.', 'danger')
                return redirect(url_for('register'))

            flash(f'Incorrect OTP! Attempt {session["wrong_attempts"]}/3', 'danger')

    return render_template('verify_otp.html', form=form)

@app.route('/resend-otp')
def resend_otp():
    if (email := session.get('temp_email')):
        otp = random.randint(100000, 999999)
        session['otp'] = otp
        session['otp_time'] = int(time.time())

        msg = Message('Your OTP Code', sender='your_email@gmail.com', recipients=[email])
        msg.body = f"Your OTP is {otp}. It expires in 5 minutes."
        mail.send(msg)

        flash('New OTP sent to your email. Please verify.', 'info')
        return redirect(url_for('verify_otp'))
    else:
        flash('No session data found. Please start registration again.', 'danger')
        return redirect(url_for('register'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['email'] = email
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('login'))

    return f'Welcome {session["email"]}! You are logged in securely.'

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out due to inactivity or logout request.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 