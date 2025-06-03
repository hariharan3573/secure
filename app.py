from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import random, time
from datetime import timedelta
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp
import secrets  
import os  
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = secrets.token_hex(32)  
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_SENDER')  
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSKEY')  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
app.config['SESSION_COOKIE_SAMESITE'] = 'strict' 
app.config['SESSION_COOKIE_SECURE'] = True  
app.config['SESSION_COOKIE_HTTPONLY'] = True  

mail = Mail(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    secret_key = db.Column(db.String(128), nullable=False)
    
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(),Length(min=8),Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])', message="Password must include upper, lower, number, and special character.")])
    captcha = StringField('CAPTCHA', validators=[DataRequired()])
    submit = SubmitField('Register')

class OTPForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[DataRequired()])
    submit = SubmitField('Verify OTP')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

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

    if request.method == 'GET':
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)
        session['captcha_answer'] = num1 + num2
        session['captcha_question'] = f'What is {num1} + {num2}?'

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        captcha = form.captcha.data

        if int(captcha) != session.get('captcha_answer'):
            flash('Incorrect CAPTCHA answer!')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'warning')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        otp = random.randint(100000, 999999)

        session['temp_email'] = email
        session['temp_password'] = hashed_password
        session['otp'] = otp
        session['otp_time'] = int(time.time())
        session['wrong_attempts'] = 0

        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"Your OTP is {otp}. It expires in 5 minutes."
        mail.send(msg)

        flash('OTP sent to your email. Please verify.', 'info')
        return redirect(url_for('verify_otp'))

    return render_template('register.html', form=form, captcha_question=session.get('captcha_question'))

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    form = OTPForm()
    if form.validate_on_submit():
        entered_otp = form.otp.data
        saved_otp = session.get('otp')
        otp_time = session.get('otp_time')

        if not otp_time or time.time() - otp_time > 300:
            flash('OTP expired! Please register again.', 'danger')
            return redirect(url_for('register'))

        if str(saved_otp) == entered_otp:
            email = session['temp_email']
            password = session['temp_password']
            new_user = User(email=email, password=password, secret_key=secrets.token_hex(16))  
            db.session.add(new_user)
            db.session.commit()

            session.clear()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            session['wrong_attempts'] += 1
            if session['wrong_attempts'] >= 3:
                session.clear()
                flash('Too many incorrect attempts. Registration failed.', 'danger')
                return redirect(url_for('register'))
            flash(f"Incorrect OTP! Attempt {session['wrong_attempts']}/3", 'danger')

    return render_template('verify_otp.html', form=form)

@app.route('/resend-otp')
def resend_otp():
    email = session.get('temp_email')
    if not email:
        flash('Session expired. Please register again.', 'danger')
        return redirect(url_for('register'))

    otp = random.randint(100000, 999999)
    session['otp'] = otp
    session['otp_time'] = int(time.time())

    msg = Message('Your New OTP', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f"Your new OTP is {otp}. It expires in 5 minutes."
    mail.send(msg)

    flash('A new OTP was sent to your email.', 'info')
    return redirect(url_for('verify_otp'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):

            session['email'] = user.email
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid email or password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=session['email']).first()
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    print("Before clear:", session)
    session.clear()
    print("After clear:", session)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

