from flask import render_template, session, redirect, request
from functools import wraps
import string
import smtplib
import random
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

# Set up API
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login?next=" + request.path)
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("status") is None:
            return redirect("/login?next=" + request.path)
        elif session.get('status') != 'admin':
            return render_template('alert.html', message="403 FORBIDDENED", info="The page you want access is only available for admins.")
        return f(*args, **kwargs)
    return decorated_function

def staff_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("status") is None:
            return redirect("/login?next=" + request.path)
        elif session.get('status') != 'staff' or session.get('status') != 'admin':
            return render_template('alert.html', message="403 FORBIDDENED", info="The page you want access is only available for staff and admins.")
        return f(*args, **kwargs)
    return decorated_function


# Define Random string for email verification
def randomString(stringLength=75):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


# Define email verfication is required
def verification_required(f):
    """
    Decorate routes to require email verification.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("verification") is None:
            return redirect("/login?next=" + request.path)
        elif session.get('verification') == 'no':
            return redirect("/verification")
        return f(*args, **kwargs)
    return decorated_function

# send auto-email with verification link
def send_email(receiver, subject, body):
    try:
        server = smtplib.SMTP('smtp.gmail.com:587')
        server.ehlo()
        server.starttls()
        server.login('longlivesaltienation@gmail.com', 'longlivesalties')
        msg = f"Subject: {subject}\n\n{body}"
        server.sendmail('longlivesaltienation@gmail.com', receiver, msg)
        server.quit()
    except:
        print('An error occurred while sending email')