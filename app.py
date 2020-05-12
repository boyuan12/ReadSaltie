import os
from datetime import date, timedelta, datetime
import calendar
import json
import string
import random

from flask import Flask, flash, render_template, session, request, redirect, url_for, abort, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from tempfile import mkdtemp
import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import update, desc, text, asc
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from static import *


# Configure basic app information
app = Flask(__name__, static_url_path='/static')
UPLOAD_FOLDER = "/home/readsaltie/ReadSaltie/static"
app.secret_key = "secret key"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

maintenance_mode = False
@app.before_request
def check_for_maintenance():
    if maintenance_mode:
        abort(503)
    else:
        redirect(request.path)

@app.errorhandler(503)
def maintenance(error):
    return '<h1>503 Under Maintenance</h1>Hello, this site is currently under maintenance right now, this time period will approximately end between 1-3hrs. If we need to extend that time, further notice will be displayed on this page. Thank you for your patience!', 503

# securities
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


# Set up SQLAlchemy Connection
SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="readsaltie",
    password="databaseforrs",
    hostname="readsaltie.mysql.pythonanywhere-services.com",
    databasename="readsaltie$default",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# SQL ORM database models


class User(db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(4096))
    username = db.Column(db.String(4096))
    password = db.Column(db.String(4096))
    status = db.Column(db.String(4096))
    verification = db.Column(db.String(4096))
    picture = db.Column(db.Text)


class Post(db.Model):

    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(4096))
    contents = db.Column(db.Text)
    location = db.Column(db.String(4096))
    timestamp = db.Column(db.String(4096))


class Book(db.Model):

    __tablename__ = "books"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(4096))
    timestamp = db.Column(db.String(4096))
    title = db.Column(db.String(4096))
    description = db.Column(db.String(4096))
    image_name = db.Column(db.String(4096))
    embedCode = db.Column(db.Text)
    contest = db.Column(db.String(10))
    rating = db.Column(db.String(10))
    view = db.Column(db.Integer)
    access = db.Column(db.Text)
    view_status = db.Column(db.Text)


class Comment(db.Model):

    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(4096))
    text = db.Column(db.Text)
    location = db.Column(db.String(4096))


class Error(db.Model):

    __tablename__ = "errors"

    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(4096))
    method = db.Column(db.String(100))
    detail = db.Column(db.Text)


class Course(db.Model):

    __tablename__ = "courses"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    category = db.Column(db.String(100))


class Course_Content(db.Model):

    __tablename__ = "courses-contents"

    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey("courses.id"))
    contents = db.Column(db.Text)

class Contest(db.Model):

    __tablename__ = "contests"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    winner = db.Column(db.Text)
    begin = db.Column(db.String(20))
    end = db.Column(db.String(20))

class Follower(db.Model):

    __tablename__ = "followers"

    id = db.Column(db.Integer, primary_key=True)
    following_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    owner_id = db.Column(db.Integer)

class Notification(db.Model):

    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    to_id = db.Column(db.Integer)
    message = db.Column(db.Text)
    link = db.Column(db.Text)
    status = db.Column(db.String(100))

class Saved_Book(db.Model):

    __tablename__ = 'saved_book'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    title = db.Column(db.String(100))
    description = db.Column(db.String(4096))
    contents = db.Column(db.Text)


class Analytic(db.Model):

    __tablename__ = 'analytic'

    id = db.Column(db.Integer, primary_key=True)
    utm_source = db.Column(db.String(100))
    datetime = db.Column(db.DateTime)


# Create all database
db.create_all()


# Index route
@app.route("/")
def home():

    if request.args.get("utm_source"):
        analytics = Analytic(utm_source=request.args.get("utm_source"), datetime=datetime.datetime.now())
        db.session.add(analytics)
        db.session.commit()

    posts = Post.query.filter_by(location='Event')
    return render_template("index.html", posts=posts)

# register route
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        # check for required fields are all filled in (in case js is disabled)
        if not request.form.get("username") or not request.form.get('password') or not request.form.get('email') or not request.form.get('confirmation'):
            flash("Make sure you filled out all required fields.", category='danger')
            return redirect('/register')

        # Set up variables for later use
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        # Check for password confirmation (in case js is disabled)
        if password != confirmation:
            flash('Incorrect password confirmation', category='danger')
            return redirect('/register')

        # Check for username/email is already registered or not
        user = User.query.filter_by(username=username).first()
        userEmail = User.query.filter_by(email=email).first()
        try:
            if user.username == username:
                flash('Username already exist, probably try forgot password.', category='danger')
                return redirect('/register')
        except AttributeError:
            pass
        try:
            if userEmail.email == email:
                flash('Email already exist, probably try forgot password.', category='danger')
                return redirect('/register')
        except AttributeError:
            pass

        # Generate password and verification string (see static.py for randomString function definition)
        pwHash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        verificationCode = randomString(75)

        file = request.files["image"]
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], file.filename))

        # Add user
        registrant = User(email=email, username=username, password=pwHash, status="user", verification=verificationCode, picture=file.filename)
        db.session.add(registrant)
        db.session.commit()

        # Send email (see static.py for send_email function definition)
        send_email(email, "Verify your Saltie Nation Account!", "Click following link to access " +
                   "https://readsaltie.pythonanywhere.com/verification/" + verificationCode)

        # return user to login route and login
        return redirect("/login")
    else:
        # return register.html if it's GET method
        return render_template('register.html')


# Login route definition
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        # Get required information
        username = request.form.get('username')
        password = request.form.get('password')

        # Get user's information
        user = User.query.filter_by(username=username).first()

        # Check and see if its valid info or not
        if not user:
            flash('Wrong username', category='danger')
            return redirect('/login')
        if user.password == '(Google)':
            return redirect('/google')
        if not check_password_hash(user.password, password):
            flash('Wrong password', category='danger')
            return redirect('/login')

        # Set up session, verification, etc.
        global user_id
        user_id = user.id
        global status
        status = user.status
        verificationStatus = user.verification
        if verificationStatus == 'verified':
            session['verification'] = 'verified'
        else:
            session['verification'] = 'no'
        session["user_id"] = user.id
        session["username"] = username
        session['status'] = status
        session['email'] = user.email

        notifications = Notification.query.filter_by(to_id=session.get('user_id'))
        notification_count = 0
        for notification in notifications:
            if notification.status == 'unread':
                notification_count += 1
        session['notification_count'] = notification_count

        # Check if user is temporary banned from website
        if 'banned' in status is not True:
            session.clear()
            return render_template('alert.html', message="Hello, you've been temporarily banned from our website. Please contact administrator for more detail")

        # if it redirect from other route, next route maybe provided and will redirect user to the corresponding route
        if request.args.get('next'):
            return redirect(request.args.get('next'))

        # redirect to homepage as default action (if next parameter is not provided)
        return redirect('/')
    else:
        return render_template('login.html')


# route for admin-user dashboard
@app.route("/admin/users")
@login_required
def admin_users():
    # check for valid status (only admin and staff-(generalist)) have right to access
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        abort(403)

    # get all the user from database and send it to admin-user.html
    all_rows = User.query.all()
    return render_template('admin-users.html', users=all_rows)


# route for admin-delete user
@app.route("/admin/delete", methods=['GET', 'POST'])
@login_required
def delete_user():
    # check for valid status (only admin can delete user)
    if session['status'] == 'user' or session['status'] == 'staff-(generalist)' or session['status'] == 'staff-(user manager)':
        abort(403)

    if request.method == 'POST':
        # Get required information
        id = request.form.get('id')
        comment = request.form.get('comment')
        user = User.query.filter_by(id=id).first()
        email = user.email
        username = user.username

        # Send removal notification email
        send_email(email, 'Removal Notification from Official Saltie National Broadcasting Channel', 'Dear ' + username + "\n, You have been removed from Official Saltie National Broadcasting Channel. There is a comment from administrator who handle this. \n" +
                   comment + "\n Thank you, admin from Official Saltie National Broadcasting Channel \n If you feel it's not fair, please send an email to us")

        # Delete user and commit
        User.query.filter(User.id == id).delete(synchronize_session='evaluate')
        db.session.commit()
        return redirect("/admin/users")
    else:
        return render_template("user-delete-form.html")


# route for modify user's status ONLY
@app.route("/admin/modify", methods=['GET', 'POST'])
@login_required
def modify_user():
    # Check for valid status, only admin and staff-(generalist) can access
    if session['status'] == 'user' or session['status'] == 'staff-(generalist)':
        abort(403)

    if request.method == 'POST':
        # Get required informations
        id = request.form.get('id')
        status = request.form.get('status')
        identifier = request.form.get('identifier')

        # modify user's status
        user = User.query.filter_by(id=id).first()
        if status == 'staff':
            user.status = status + "-" + "(" + identifier + ")"
        else:
            user.status = status
        db.session.commit()
        return redirect("/admin/users")
    else:
        return render_template('user-status-form.html')


# route for add-file
@app.route("/admin/add-file", methods=['GET', 'POST'])
@login_required
def add_file():
    # check for valid status, only admin can access
    if session['status'] == 'user' or session['status'] == 'staff-(generalist)' or session['status'] == 'staff-(user manager)':
        abort(403)

    if request.method == 'POST':

        # upload file
        file = request.files["file"]
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], file.filename))
        return render_template('index.html')
    else:
        return render_template("admin-home.html")


# route for logout
@app.route("/logout")
@login_required
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/verification")
def verification():
    return render_template("verification.html")

# verification with a token roue
@app.route("/verification/<string:token>")
def verify(token):

    # create an empty dict
    verificationDict = {}

    # find the user with the token
    verifyToken = User.query.filter_by(verification=token).first()

    # add ALL token information to verificationDict
    try:
        verificationDict.update({verifyToken.verification: verifyToken.id})

    # except error if no token find
    except AttributeError:
        flash('No forgot password token found. Is this the newest token or did you already clicked?', category='danger')
        return redirect('/verification')

    # if token found, change user's status to verified
    if token in verificationDict:
        idOfUser = verificationDict[token]
        user = User.query.filter(User.id == idOfUser).one()
        del verificationDict[user.verification]
        user.verification = 'verified'
        db.session.commit()
        session['verification'] = 'verified'
        flash('Your account is successfully verified!', category='success')
        return redirect('/')
    else:
        flash('No such verification string', category='danger')
        return redirect('/verification')


@app.route("/forgotpassword", methods=['GET', 'POST'])
def forgotpassword():

    # create forgotPasswordDict
    global forgotPasswordDict
    forgotPasswordDict = {}

    if request.method == 'POST':

        # check for required field to fill out
        if not request.form.get('email'):
            flash('Please fill out all required field(s)', category='danger')
            return redirect('/forgotpassword')

        # Generate a code that will send to user
        forgotPasswordCode = randomString(75)
        email = request.form.get('email')

        # See if user exists
        try:
            user = User.query.filter_by(email=email)
            user_email = user.email
        except:
            flash('Email not found, is this right email address? Did you registered using this email address?', category='danger')
            return redirect('/forgotpassword')

        # Add this to dict, and send email
        forgotPasswordDict.update({forgotPasswordCode: email})
        send_email(email, 'Important! Request Password Change at ReadSaltie', 'Important, someone request a password change for your account at Saltie National Broadcasting Channel. If you did, click followling link to reset your password: https://readsaltie.pythonanywhere.com/forgotpassword/' +
                   forgotPasswordCode + ' If you didn\'t request it, don\'t be worry, your password is still the same.')
        return render_template("success.html", message='Please check your email address for link to reset your password.')
    else:
        return render_template('forgot-password.html')


# forgotpassword route - logic similar to /verification/<string:token>
@app.route("/forgotpassword/<string:token>")
def getnewpassword(token):

    # check see if the token is in the forgotPasswordDict
    if token in forgotPasswordDict:

        # store email identified into a global variable
        global forgotEmail
        forgotEmail = forgotPasswordDict[token]

        # delete this token immediately
        del forgotPasswordDict[token]

        # select all users
        users = User.query.all()

        # check if user's email is in the database
        emailList = []
        for user in users:
            emailList.append(user.email)
        if forgotEmail in emailList:
            return render_template("new-password.html", email=forgotEmail)

        # return if email isn't exist
        else:
            flash('Error.', category='danger')
            return redirect('/forgotpassword')
    else:
        flash('Forgot password token not found.', category='danger')
        return redirect('/forgotpassword')


# route for user to enter new password
@app.route("/new-password", methods=['GET', 'POST'])
def new_password():
    if request.method == 'POST':

        # get all required fields
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        # check see if password = confirmation
        if password != confirmation:
            flash('Password confirmation not correct', category='danger')
            return redirect('/forgotpassword')

        # commit the change
        pwHash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        user = User.query.filter_by(email=forgotEmail).first()
        user.password = pwHash
        db.session.commit()
        return redirect("/")

    else:

        try:
            return render_template('new-password.html', email=forgotEmail)
        except NameError:
            flash('System didn\'t found your email address, maybe try to do forgot password first?', category='danger')
            return redirect('/forgotpassword')


# 404 error handler
@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('alert.html', message='404 NOT FOUND'), 404


# 500 error handler
@app.errorhandler(500)
def internal_server_error(e):
    error = Error(location=request.url, method=request.method, detail=str(e.args))
    db.session.add(error)
    db.session.commit()
    return render_template('alert.html', message='500 INTERNAL SERVER ERROR: This is SNBC Channel Staff. Sorry, we were expriencing some technical issues. Please Understand this site is under active development right now. Sorry.', info=str(e.args)), 500


# route for editing page
@app.route("/admin/edit/homepage", methods=['GET', 'POST'])
def edit_homepage():

    # check for valid status
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        abort(403)

    if request.method == 'POST':

        # Get all required infomration
        htmlScript = request.form.get('html-script')
        location = request.form.get('location')

        # Get time
        ts = datetime.datetime.now().timestamp()
        readable = datetime.datetime.fromtimestamp(ts).isoformat()

        # Add to database
        post = Post(username=session['username'], contents=htmlScript, location=location, timestamp=readable)
        db.session.add(post)
        db.session.commit()

        return render_template('success.html', message='submit success')
    else:
        return render_template("admin-edit-homepage.html")


# Headline page (same logic as "/")
@app.route("/headline")
def headline():
    posts = Post.query.filter_by(location='headline')
    return render_template("headline.html", posts=posts)


# music route
@app.route('/music')
def music():
    return render_template('music.html')


# Books route, show all the books
@app.route('/books', methods=['GET'])
@verification_required
def books():

    # if user query for certain book
    if request.args.get('title'):

        # get title from GET request
        title = request.args.get('title')

        # Search the database
        search = "%{}%".format(title)
        books = Book.query.filter(Book.title.like(search)).order_by(desc(Book.id))
        return render_template('book-searched.html', books=books)
    else:
        books = Book.query.order_by(desc(Book.id))
        return render_template('books.html', books=books)


# Add books, need verification
@app.route('/books/add', methods=['GET', 'POST'])
@verification_required
def book_add():

    if request.method == 'POST':

        # get request info
        if not request.form.get('title'):
            return render_template('alert.html', message='You didn\'t provide title')
        if not request.form.get('description'):
            return render_template('alert.html', message='You didn\'t provide desc')
        if not request.form.get('embed'):
            return render_template('alert.html', message='You didn\'t provide embed')

        # Check for XSS security
        if "script" in request.form.get('embed') is not True or "onerror" in request.form.get('embed') is not True:
            send_email(session['email'], 'Temporary Banned From ReadSaltie',
                       'Dear user, Your are temporary banned from ReadSaltie due to violation of term of use and potential opporotunity of hacking. There should be a staff responding to this incident around 72 hours. Feel free to email back if you have any problem. Thanks.')
            send_email('longlivesaltienation@gmail.com',
                       'Banned Pending Request', 'Staff, username: {}, email: {}, have been temporary banned from website due to B1. Embed Code: {}, please respond within 72 hours. Thanks.'.format(session['username'], session['email'], request.form.get('embed')))

            # Banned user to database
            user = User.query.filter_by(email=session['email']).first()
            user.status = 'banned'
            db.session.commit()
            session.clear()
            return render_template('alert.html', message="Sorry, we are in suspicious that your embed code may contain something that is not supposed to be in there. You are temporaily banned from using this website. Admin will be notified and an auto-generated email will send to your inbox. Thanks.")

        # if passed XSS checking, add to the database
        title = request.form.get('title')
        titleDb = Book.query.filter_by(title=title).first()

        if "?" in title:
            return render_template('alert.html', message='Sorry, ? is restricted symbol. You may not publish any book with title that contains ?.')

        # Get required information
        description = request.form.get('description')
        embed = request.form.get('embed')

        if "iframe" in embed is False:
            embed = '<iframe srcdoc=' + embed + ' width="1000" height="1000" frameborder="0"></iframe>'


        # Get current time
        ts = datetime.datetime.now().timestamp()
        timestamp = datetime.datetime.fromtimestamp(ts).isoformat()

        # Save image
        file = request.files["image"]
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], file.filename))

        # Add special admin badge in author when its author is an admin
        if session['status'] == 'admin':
            book = Book(username=session['username'] + " (admin)", timestamp=timestamp,
                        title=title, description=description, image_name=file.filename, embedCode=embed, rating='No rating', view=0, contest=request.form.get('contest'), access=randomString(10), view_status=request.form.get('view_status'))
        elif session['status'] == 'staff':
            book = Book(username=session['username'] + " (staff)", timestamp=timestamp,
                        title=title, description=description, image_name=file.filename, embedCode=embed, rating='No rating', view=0, contest=request.form.get('contest'), access=randomString(10), view_status=request.form.get('view_status'))
        else:
            book = Book(username=session['username'], timestamp=timestamp, title=title,
                        description=description, image_name=file.filename, embedCode=embed, rating='No rating', view=0, contest=request.form.get('contest'), access=randomString(10), view_status=request.form.get('view_status'))

        # Add book
        db.session.add(book)
        db.session.commit()

        # Add Notification
        followers = Follower.query.filter_by(following_id=session.get('user_id'))
        for follower in followers:
            notification = Notification(to_id=follower.owner_id, message='{} published a new book, called {}.'.format(session.get('username'), title), link="/books/read/{}".format(title), status='unread')
            db.session.add(notification)
            db.session.commit()

        return render_template('success.html', message='success', link="/books/read/" + title)

    else:
        return render_template('admin-books-add.html')


# admin view book interface
@app.route('/admin/books/all')
@login_required
def admin_book_all():

    # Check for valid status
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")

    # Search the book, order by latest order
    books = Book.query.order_by(desc(Book.id))
    return render_template('admin-books-all.html', books=books)


# Delete books - admin
@app.route('/admin/books/delete', methods=['GET'])
@login_required
def admin_book_delete():

    # Check for valid status
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")

    # Check for required credentials
    if not request.args.get('book'):
        return render_template('alert.html', message="Missing Infos")

    # Delete books from database and image from storage
    id = request.args.get('book')
    book = Book.query.filter_by(id=id).first()
    image_name = book.image_name
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image_name))
    except FileNotFoundError:
        pass
    Book.query.filter(Book.id == id).delete(synchronize_session='evaluate')
    db.session.commit()
    return render_template('success.html', message='Delete Success', link="/admin/books/all")


# Read a book
viewRanList = [];

@app.route('/books/read/<string:access>')
def read_book(access):

    # find appropriate title based on route
    titleDb = Book.query.filter_by(access=access).all()

    # generate random book string
    random_str = randomString(75)
    viewRanList.append(random_str)

    # Check for all title, see which one matches
    for titles in titleDb:
        if titles.access == access:
            title = titles.title
            comments = Comment.query.filter_by(location=title).all()
            return render_template('book-read.html', id=titles.id, embedCode=titles.embedCode, title=titles.title, comments=comments, randomString=random_str)

    # Return this if no book found
    return render_template('alert.html', message='NOT FOUND')

@app.route('/books/<int:book_id>/view/<string:random>')
def add_view(book_id, random):

    if random not in viewRanList:
        return jsonify('Wrong Random String')

    viewRanList.remove(random)

    book = Book.query.filter_by(id=book_id).first()
    try:
        book.view += 1
    except TypeError:
        book.view = 1
    db.session.commit()

    return jsonify('success')

# get user's comment
@app.route("/comment", methods=['POST'])
@login_required
@verification_required
def comment():

    # check for required information
    if not request.form.get('comment'):
        return render_template('alert.html', message='Make sure you filled out all required field(s)!')

    # Get comment and add to database
    comment = request.form.get('comment')
    location = request.form.get('location')
    comments = Comment(username=session['username'], text=comment, location=location)
    db.session.add(comments)
    db.session.commit()
    return redirect("/books/read/" + location)


# user submit rating
@app.route('/rating', methods=['POST'])
@login_required
@verification_required
def rating():

    # Check for required fields
    if not request.form.get('rating'):
        return render_template('alert.html', message='Make sure you filled out all required field(s)!')

    # Query rating
    rating = request.form.get('rating')
    location = request.form.get('location')
    ratingDb = Book.query.filter_by(title=location).first()

    # ?
    if ratingDb.rating == "No rating":
        ratingDb.rating = rating
        db.session.commit()
        return render_template('success.html', message='success rating')
    else:
        ratingInDb = float(ratingDb.rating)
        newRating = (ratingInDb + float(rating)) / 2
        ratingDb.rating = newRating
        db.session.commit()
        return render_template('success.html', message='success rating', link="/books/read/" + location)


# profile information
@app.route('/profile')
@login_required
def profile():
    if session.get('status') == 'admin':
        books = Book.query.filter_by(username=session.get('username') + ' (admin)')
    elif session.get('status') == 'staff':
        books = Book.query.filter_by(username=session.get('username') + ' (staff)')
    else:
        books = Book.query.filter_by(username=session.get('username'))

    following = Follower.query.join(User, Follower.following_id == User.id).add_columns(User.username, Follower.following_id).filter(Follower.owner_id == session.get('user_id'))
    saved_books = Saved_Book.query.filter_by(user_id=session.get('user_id'))

    return render_template('profile.html', books=books, following=following, saved_books=saved_books)


# user can edit their username
@app.route('/profile/username', methods=['POST'])
def change_username():
    email = session['email']
    new_username = request.form.get('new_username')
    user = User.query.filter_by(email=email).first()
    user.username = new_username
    email = user.email
    db.session.commit()
    session['username'] = new_username
    send_email(email, "IMPORTANT: YOUR USERNAME CHANGED",
               "Hello, your account at https://readsaltie.pythonanywhere.com has just changed its USERNAME.")
    return render_template('success.html', message='username changed success.')


# user can edit their password
@app.route('/profile/password', methods=['POST'])
def change_password():
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    new_password_con = request.form.get('new_password_confirmation')
    if new_password != new_password_con:
        return render_template('alert.html', message='Wrong password confirmation')
    pwHash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=8)
    user = User.query.filter_by(username=username).first()
    user.password = pwHash
    db.session.commit()
    email = user.email
    send_email(email, "IMPORTANT: YOUR PASSWORD CHANGED",
               "Hello, your account at https://readsaltie.pythonanywhere.com has just changed its password.")
    return render_template('success.html', message='password changed success.')


# user can edit their email
@app.route('/profile/email', methods=['POST'])
def change_email():
    username = request.form.get('username')
    new_email = request.form.get('new_email')
    verificationCode = randomString(75)
    user = User.query.filter_by(username=username).first()
    user.email = new_email
    user.verification = verificationCode
    db.session.commit()
    session['verification'] = 'no'
    send_email(new_email, "Verify your Saltie Nation Account!", "Click following link to access " +
               "https://readsaltie.pythonanywhere.com/verification/" + verificationCode)
    send_email(new_email, "IMPORTANT: YOUR EMAIL CHANGED",
               "Hello, your account at https://readsaltie.pythonanywhere.com has just changed its email address.")
    return render_template('success.html', message="Email changed success, check your email for verification.")


@app.route("/profile/delete", methods=["POST"])
def delete():

    User.query.filter_by(id=session.get("user_id")).delete()
    db.session.commit()
    session.clear()
    return redirect("/")

@app.route('/profile/<string:username>/delete/<int:book_id>')
@login_required
def profile_delete_book(username, book_id):

    if session.get('username') != username:
        abort(403)

    Book.query.filter(Book.id == book_id).delete(synchronize_session='evaluate')
    db.session.commit()

    flash('Delete Success', category='success')
    return redirect(url_for('profile'))

# see all admin posts
@app.route('/admin/post/all')
def post_all():
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")
    posts = Post.query.all()
    return render_template('admin-post-all.html', posts=posts)


@app.route('/admin/post/delete', methods=['GET'])
def post_delete():
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")
    if not request.args.get('id'):
        return render_template('alert.html', message='GET: NOT PROVIDE id')
    id = request.args.get('id')
    Post.query.filter(Post.id == id).delete(synchronize_session='evaluate')
    db.session.commit()
    return render_template('success.html', message="Success!", link="/admin/post/all")


@app.route('/admin/comment/all')
@login_required
def comment_all():
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")
    comments = Comment.query.all()
    return render_template('admin-comment-all.html', comments=comments)


@app.route('/admin/comment/delete', methods=['GET'])
def comment_delete():
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")
    if not request.args.get('id'):
        return render_template('alert.html', message='GET: NOT PROVIDE id')
    id = request.args.get('id')
    Comment.query.filter(Comment.id == id).delete(synchronize_session='evaluate')
    db.session.commit()
    return redirect('/admin/comment/all')


@app.route('/admin/error/all')
def error_all():
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")
    errors = Error.query.all()
    return render_template('admin-error-all.html', errors=errors)


@app.route('/google2cea6360674968aa.html')
def google_site_verification():
    return render_template('google2cea6360674968aa.html')


@app.route('/term')
def term():
    return render_template('term.html')

google_blueprint = make_google_blueprint(client_id='260205772815-ho1c7bv4o7ij2rf4pckop1uuurshdumn.apps.googleusercontent.com', client_secret='gUT0d2u-H9ZNi8oLOWMSsz4Z',
                                         scope=['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'openid'])
app.register_blueprint(google_blueprint, url_prefix='/google_login')

# Google login
@app.route('/google')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get("/oauth2/v1/userinfo")
    assert resp.ok, resp.text
    return redirect('/')


@oauth_authorized.connect_via(google_blueprint)
def google_authorized(blueprint, token):
    resp = google.get("/oauth2/v1/userinfo")
    assert resp.ok, resp.text
    email = resp.json()['email']
    image = resp.json()['picture']
    if resp.json()['verified_email'] != True:
        return render_template('alert.html', message='You must verify your Google Account\' email first.')
    userEmail = User.query.filter_by(email=email).first()
    try:
        if userEmail.email == email:
            session["user_id"] = userEmail.id
            session["username"] = userEmail.username
            session['status'] = userEmail.status
            session['email'] = userEmail.email
            session['verification'] = userEmail.verification
            session['oauth'] = 'Google'
            session['verification'] = 'verified'
            notifications = Notification.query.filter_by(to_id=session.get('user_id'))
            notification_count = 0
            for notification in notifications:
                if notification.status == 'unread':
                    notification_count += 1
            session['notification_count'] = notification_count
            if userEmail.status == 'banned':
                session.clear()
                flash('Hello, you are temporaily banned from ReadSaltie, please wait for further notice. Thanks', category='danger')
                return redirect('/')
            else:
                return redirect('/')
    except AttributeError:
        pass
    registrant = User(email=email, username=email, password="(Google)", status="user", picture=image)
    db.session.add(registrant)
    db.session.commit()
    userAfter = User.query.filter_by(email=email).first()
    session["user_id"] = userAfter.id
    session["username"] = email
    session['status'] = userAfter.status
    session['email'] = email
    session['verification'] = 'verified'
    session['oauth'] = 'Google'
    if userAfter.status == 'banned':
        flash('Hello, you are temporaily banned from ReadSaltie, please wait for further notice. Thanks', category='danger')
    else:
        notifications = Notification.query.filter_by(to_id=session.get('user_id'))
        notification_count = 0
        for notification in notifications:
            if notification.status == 'unread':
                notification_count += 1
        session['notification_count'] = notification_count
        return redirect('/')


@app.route('/admin/send-email', methods=['GET', 'POST'])
@admin_required
def admin_send_email():
    if request.method == 'POST':

        if request.form.get('admin'):
            userEmail = User.query.filter_by(status='admin')
            for user in userEmail:
                send_email(user.email, request.form.get('subject'), request.form.get('body'))
            return redirect('/admin/send-email')

        if request.form.get('staff'):
            userEmail = User.query.filter_by(status='staff-(generalist)')
            for user in userEmail:
                send_email(user.email, request.form.get('subject'), request.form.get('body'))
            userEmail = User.query.filter_by(status='staff-(user manager)')
            for user in userEmail:
                send_email(user.email, request.form.get('subject'), request.form.get('body'))
            return redirect('/admin/send-email')

        if request.form.get('user'):
            userEmail = User.query.filter_by(status='user')
            for user in userEmail:
                send_email(user.email, request.form.get('subject'), request.form.get('body'))
            return redirect('/admin/send-email')

        if request.form.get('everyone'):
            userEmail = User.query.all()
            for user in userEmail:
                send_email(user.email, request.form.get('subject'), request.form.get('body'))
            return redirect('/admin/send-email')

        if request.form.get('email'):
            userEmail = User.query.all()
            for user in userEmail:
                if user.email == request.form.get('email'):
                    send_email(user.email, request.form.get('subject'), request.form.get('body'))
                    return redirect('/admin/send-email')
            return '<h1>No user found</h1>'

    else:
        return render_template('admin-send-email.html')


@app.route('/survey')
@login_required
def survey():

    return render_template('survey.html')


@app.route('/profile/<string:username>')
@login_required
def public_profile(username):

    user = User.query.filter_by(username=username).first()

    try:
        username = user.username
    except:
        abort(404)

    if user.status == 'admin':
        books = Book.query.filter_by(username=username + " (admin)")
    elif user.status == 'staff':
        books = Book.query.filter_by(username=username + " (staff)")
    else:
        books = Book.query.filter_by(username=username)

    return render_template('public-profile.html', user=user, books=books)


@app.route('/follow/<int:user_id>')
@login_required
def follow(user_id):

    users = Follower.query.filter_by(owner_id=session.get('user_id'))
    for user in users:
        if user.following_id == user_id:
            return render_template('alert.html', message='Already Followed')

    if user_id == session.get('user_id'):
        return render_template('alert.html', message='You can\'t follow yourself.')

    follower = Follower(following_id=user_id, owner_id=session.get('user_id'))
    db.session.add(follower)
    db.session.commit()

    return render_template('success.html', message='Follow Success')


@app.route('/notifications')
@login_required
def notification():

    notifications = Notification.query.filter_by(to_id=session.get('user_id'))

    for notification in notifications:
        notification.status == 'read'
        db.session.commit()

    return render_template('notifications.html', notifications=notifications)


@app.route('/book/add-manually', methods=['GET', 'POST'])
@login_required
def add_book_editor():

    if request.method == 'POST':

        if not request.form.get('title') or not request.form.get('contents') or not request.form.get('description'):
            return jsonify({'error': 'please fill out ALL required fields'})

        title = request.form.get('title')
        contents = request.form.get('contents')
        description = request.form.get('description')

        book_saved = Saved_Book.query.filter_by(user_id=session.get('user_id'))
        for book in book_saved:
            if book.title == title:
                book.contents=contents
                book.description=description
                db.session.commit()
                return jsonify({'success': 'success'})

        book = Saved_Book(user_id=session.get('user_id'), title=title, contents=contents)

        db.session.add(book)
        db.session.commit()

        return jsonify({'success': 'success'})
    else:
        return render_template('add-book-editor.html')


@app.route('/saved_book/edit/<string:title>')
@login_required
def saved_book_edit(title):

    book = Saved_Book.query.filter_by(title=title).first()

    if book.user_id != session.get('user_id'):
        abort(403)

    return render_template('saved-book-edit.html', book=book)


@app.route('/saved_book/delete/<string:title>')
@login_required
def saved_book_delete(title):

    book = Saved_Book.query.filter_by(title=title).first()

    if book.user_id != session.get('user_id'):
        abort(403)

    Saved_Book.query.filter(Saved_Book.title == title).delete(synchronize_session='evaluate')
    db.session.commit()

    flash('success', category='success')
    return redirect(url_for('profile'))


@app.route('/unfollow/<int:user_id>')
@login_required
def unfollow(user_id):

    if user_id == session.get('user_id'):
        return render_template('alert.html', message='You can\'t follow yourself.')

    Follower.query.filter(Follower.following_id == user_id).delete(synchronize_session='evaluate')
    db.session.commit()

    return render_template('success.html', message='Unfollow Success')


@app.route('/changelog')
def changelog():
    return render_template('changelog.html')


@app.route("/admin/analytics")
@admin_required
def analytics():

    datas = Analytic.query.all()
    return render_template("admin-analytics.html", datas=datas)