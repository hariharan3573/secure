# Secure Login Project
     A secure user authentication system built using **Flask**. It allows users to register, verify their email using an **OTP (One-Time Password)**, and log in to a protected dashboard. It includes CAPTCHA validation, strong password rules, and secure session handling.

## Description
      This is a secure Flask web application for user registration and login, built with best practices in mind. It ensures new users are human (CAPTCHA), verifies their identity via a time-limited OTP sent to email, and safely stores passwords using Bcrypt hashing.

## Technologies Used
Python 3.x ::	Core programming language
Flask	Lightweight :: Python web framework
Flask-Mail ::	Sends OTP emails to users
Flask-Bcrypt ::	Hashes and checks passwords securely
Flask-WTF ::	Handles form rendering and validation with CSRF protection
WTForms ::	Provides form fields and validators
Flask-SQLAlchemy ::	ORM for handling user data with SQLite
SQLite ::	Local database for storing user accounts
Jinja2 ::	HTML templating engine for rendering dynamic pages
python-dotenv ::	Loads .env secrets (email, password) into the app securely
HTML ::	Basic page structure 

## Installation Instructions
To run this project locally, follow the steps below:

1. Clone the repository:
   git clone https://github.com/hariharan3573/flask-auth-system.git
cd flask-auth-system

2. Create a Virtual Environment:
      python -m venv venv
      venv\Scripts\activate

3. Install Required Packages
      pip install -r requirements.txt

4. Run the Application
      python app.py

# secure
