import os

from flask import Flask, render_template, session, request, redirect, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from tempfile import mkdtemp
import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import update, desc, text
from collections import defaultdict
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from static import *

# Configure basic app information
app = Flask(__name__, static_url_path='/static')
UPLOAD_FOLDER = "/home/boyuanliu6/saltie-nation/static"
app.secret_key = "secret key"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

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
    username="boyuanliu6",
    password="database",
    hostname="boyuanliu6.mysql.pythonanywhere-services.com",
    databasename="boyuanliu6$database",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

class User(db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(4096))
    username = db.Column(db.String(4096))
    password = db.Column(db.String(4096))
    status = db.Column(db.String(4096))
    verification = db.Column(db.String(4096))

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
    rating = db.Column(db.String(10))

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

db.create_all()


@app.route("/")
def home():
    posts = Post.query.filter_by(location='Event')
    return render_template("index.html", posts=posts)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not request.form.get("username") or not request.form.get('password') or not request.form.get('email') or not request.form.get('confirmation'):
            return render_template('alert.html', message="Make sure you filled out all required fields.")
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')
        if password != confirmation:
            return render_template('alert.html', message='INCORRECT PASSWORD/CONFIRMATION')
        user = User.query.filter_by(username=username).first()
        userEmail = User.query.filter_by(email=email).first()
        try:
            if user.username == username:
                return render_template('alert.html', message='Username already registered.')
        except AttributeError:
            pass
        try:
            if userEmail.email == email:
                return render_template('alert.html', message='Email Already Registered, maybe try to forgot password?')
        except AttributeError:
            pass
        pwHash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        verificationCode = randomString(75)
        registrant = User(email=email, username=username, password=pwHash, status="user", verification=verificationCode)
        db.session.add(registrant)
        db.session.commit()
        send_email(email, "Verify your Saltie Nation Account!", "Click following link to access " + "https://boyuanliu6.pythonanywhere.com/verification/" + verificationCode)
        return render_template('success.html', message='Successfully Registered')
        return redirect("/login")
    else:
        return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user:
            return render_template('alert.html', message='Wrong Username')
        if user.password == '(Google)':
            return redirect('/google')
        if not check_password_hash(user.password, password):
            return render_template('alert.html', message='Wrong Password')
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
        if 'banned' in status is not True:
            session.clear()
            return render_template('alert.html', message="Hello, you've been temporarily banned from our website. Please contact administrator for more detail")
        if request.args.get('next'):
            return redirect(request.args.get('next'))
        return redirect('/')
    else:
        return render_template('login.html')

@app.route("/admin/users")
@login_required
# @verification_required
def admin_users():
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")
    all_rows = User.query.all()
    return render_template('admin-users.html', users=all_rows)

@app.route("/admin/delete", methods=['GET', 'POST'])
@login_required
def delete_user():
    if session['status'] == 'user' or session['status'] == 'staff-(generalist)' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")
    if request.method == 'POST':
        id = request.form.get('id')
        comment = request.form.get('comment')
        user = User.query.filter_by(id=id).first()
        email = user.email
        username = user.username
        send_email(email, 'Removal Notification from Official Saltie National Broadcasting Channel', 'Dear ' + username + "\n, You have been removed from Official Saltie National Broadcasting Channel. There is a comment from administrator who handle this. \n" + comment + "\n Thank you, admin from Official Saltie National Broadcasting Channel \n If you feel it's not fair, please send an email to us")
        User.query.filter(User.id == id).delete(synchronize_session='evaluate')
        db.session.commit()
        return redirect("/admin/users")
    else:
        return render_template("user-delete-form.html")

@app.route("/admin/modify", methods=['GET', 'POST'])
@login_required
def modify_user():
    if session['status'] == 'user' or session['status'] == 'staff-(generalist)':
        return render_template('alert.html', message="403 FORBIDDENED")
    if request.method == 'POST':
        id = request.form.get('id')
        status = request.form.get('status')
        identifier = request.form.get('identifier')
        user = User.query.filter_by(id=id).first()
        if status == 'staff':
            user.status = status + "-" + "(" + identifier + ")"
        else:
            user.status = status
        db.session.commit()
        return redirect("/admin/users")
    else:
        return render_template('user-status-form.html')

@app.route("/admin/add-file", methods=['GET', 'POST'])
@login_required
def add_file():
    if session['status'] == 'user' or session['status'] == 'staff-(generalist)' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")
    if request.method == 'POST':
        file = request.files["file"]
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], file.filename))
        return render_template('index.html')
    else:
        return render_template("admin-home.html")

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

@app.route("/verification/<string:token>")
def verify(token):
    verificationDict = {}
    verifyToken = User.query.filter_by(verification=token).first()
    try:
        verificationDict.update({verifyToken.verification: verifyToken.id})
    except AttributeError:
        return render_template('alert.html', message='NO TOKEN FOUND!')
    if token in verificationDict:
        idOfUser = verificationDict[token]
        user = User.query.filter(User.id == idOfUser).one()
        del verificationDict[user.verification]
        user.verification = 'verified'
        db.session.commit()
        session['verification'] = 'verified'
        return render_template('success.html', message='Verfied!')
    else:
        return render_template('alert.html', message='No Such Verfication String')


@app.route("/forgotpassword", methods=['GET', 'POST'])
def forgotpassword():
    global forgotPasswordDict
    forgotPasswordDict = {}
    if request.method == 'POST':
        if not request.form.get('email'):
            return render_template('alert.html', message="Please fill out all required fields")
        forgotPasswordCode = randomString(75)
        email = request.form.get('email')
        try:
            user = User.query.filter_by(email=email)
            user_email = user.email
        except:
            return render_template('alert.html', message="Email not found, is this right email address? Did you registered using this email address?")
        forgotPasswordDict.update({forgotPasswordCode: email})
        send_email(email, 'Important! Request Password Change at Saltie National Broadcasting Channel', 'Important, someone request a password change for your account at Saltie National Broadcasting Channel. If you did, click followling link to reset your password: https://boyuanliu6.pythonanywhere.com/forgotpassword/' + forgotPasswordCode + ' If you didn\'t request it, don\'t be worry, your password is still the same.')
        return render_template("success.html", message='Please check your email address for link to reset your password.')
    else:
        return render_template('forgot-password.html')

@app.route("/forgotpassword/<string:token>")
def getnewpassword(token):
    if token in forgotPasswordDict:
        global forgotEmail
        forgotEmail = forgotPasswordDict[token]
        del forgotPasswordDict[token]
        users = User.query.all()
        emailList=[]
        for user in users:
            emailList.append(user.email)
        if forgotEmail in emailList:
            return render_template("new-password.html", email=forgotEmail)
        else:
            return render_template('alert.html', message='Email address is not registered.')
    else:
        return render_template('alert.html', message='FORGOT PASSWORD TOKEN NOT FOUND!')

@app.route("/new-password", methods=['GET', 'POST'])
def new_password():
    if request.method == 'POST':
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')
        if password != confirmation:
            return render_template('alert.html', message='Confirmation must be same as new password')
        pwHash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        user = User.query.filter_by(email=forgotEmail).first()
        user.password = pwHash
        db.session.commit()
        return redirect("/")
    else:
        try:
            return render_template('new-password.html', email=forgotEmail)
        except NameError:
            return render_template('alert.html', message='System didn\'t found your email address, maybe try to do forgot password first?')

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('alert.html', message='404 NOT FOUND'), 404

@app.errorhandler(500)
def internal_server_error(e):
    error = Error(location=request.url, method=request.method, detail=str(e.args))
    db.session.add(error)
    db.session.commit()
    return render_template('alert.html', message='500 INTERNAL SERVER ERROR: This is SNBC Channel Staff. Sorry, we were expriencing some technical issues. Please Understand this site is under active development right now. Sorry.', info=str(e)), 500

@app.route("/admin/edit/homepage", methods=['GET', 'POST'])
def edit_homepage():
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")
    if request.method == 'POST':
        htmlScript = request.form.get('html-script')
        location = request.form.get('location')
        ts = datetime.datetime.now().timestamp()
        readable = datetime.datetime.fromtimestamp(ts).isoformat()
        post = Post(username=session['username'], contents=htmlScript, location=location, timestamp=readable)
        db.session.add(post)
        db.session.commit()
        return render_template('success.html', message='submit success')
    else:
        return render_template("admin-edit-homepage.html")

@app.route("/headline")
def headline():
    posts = Post.query.filter_by(location='headline')
    return render_template("headline.html", posts=posts)

@app.route('/music')
def music():
    return render_template('music.html')

@app.route('/books', methods=['GET'])
@verification_required
def books():
    if request.args.get('title'):
        title = request.args.get('title')
        search = "%{}%".format(title)
        books = Book.query.filter(Book.title.like(search)).order_by(desc(Book.id))
        return render_template('book-searched.html', books=books)
    else:
        books = Book.query.order_by(desc(Book.id))
        return render_template('books.html', books=books)

@app.route('/books/add', methods=['GET', 'POST'])
@verification_required
def book_add():
    if request.method == 'POST':
        if not request.form.get('title') or not request.form.get('description') or not request.form.get('embed'):
            return render_template('alert.html', message='Make sure you filled out all required field(s)!')

        if "script" in request.form.get('embed') is not True or "onerror" in request.form.get('embed') is not True:
            send_email(session['email'], 'Temporary Banned From ReadSaltie', 'Dear user, Your are temporary banned from ReadSaltie due to violation of term of use and potential opporotunity of hacking. There should be a staff responding to this incident around 72 hours. Feel free to email back if you have any problem. Thanks.')
            send_email('longlivesaltienation@gmail.com', 'Banned Pending Request', 'Staff, username: {}, email: {}, have been temporary banned from website due to B1. Embed Code: {}, please respond within 72 hours. Thanks.'.format(session['username'], session['email'], request.form.get('embed')))
            user = User.query.filter_by(email=session['email']).first()
            user.status = 'banned'
            db.session.commit()
            session.clear()
            return render_template('alert.html', message="Sorry, we are in suspicious that your embed code may contain something that is not supposed to be in there. You are temporaily banned from using this website. Admin will be notified and an auto-generated email will send to your inbox. Thanks.")

        title = request.form.get('title')
        titleDb = Book.query.filter_by(title=title).first()
        try:
            if titleDb.title == title:
                return render_template('alert.html', message='Title already used.')
        except AttributeError:
            pass
        description = request.form.get('description')
        embed = request.form.get('embed')
        ts = datetime.datetime.now().timestamp()
        timestamp = datetime.datetime.fromtimestamp(ts).isoformat()
        file = request.files["image"]
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], file.filename))
        if session['status'] == 'admin':
            book = Book(username=session['username'] + " (admin)", timestamp=timestamp, title=title, description=description, image_name=file.filename, embedCode=embed, rating='No rating')
        else:
            book = Book(username=session['username'], timestamp=timestamp, title=title, description=description, image_name=file.filename, embedCode=embed, rating='No rating')
        db.session.add(book)
        db.session.commit()
        return render_template('success.html', message='success', link="/books/read/" + title)
    else:
        return render_template('admin-books-add.html')

@app.route('/admin/books/all')
@login_required
def admin_book_all():
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")
    books = Book.query.order_by(desc(Book.id))
    return render_template('admin-books-all.html', books=books)

@app.route('/admin/books/delete', methods=['GET'])
@login_required
def admin_book_delete():
    if session['status'] == 'user' or session['status'] == 'staff-(user manager)':
        return render_template('alert.html', message="403 FORBIDDENED")
    if not request.args.get('book'):
        return render_template('alert.html', message="Missing Infos")
    id = request.args.get('book')
    book=Book.query.filter_by(id=id).first()
    image_name = book.image_name
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image_name))
    Book.query.filter(Book.id == id).delete(synchronize_session='evaluate')
    db.session.commit()
    return render_template('success.html', message='Delete Success', link="/admin/books/all")

@app.route('/books/read/<string:title>')
def read_book(title):
    titleDb = Book.query.filter_by(title=title).all()
    for titles in titleDb:
        if titles.title == title:
            comments = Comment.query.filter_by(location=title).all()
            return render_template('book-read.html', embedCode=titles.embedCode, title=titles.title, comments=comments) # , embedCode=titles.embedCode
    return render_template('alert.html', message='NOT FOUND')

@app.route("/comment", methods=['GET', 'POST'])
@login_required
@verification_required
def comment():
    if request.method == 'POST':
        if not request.form.get('comment'):
            return render_template('alert.html', message='Make sure you filled out all required field(s)!')
        comment = request.form.get('comment')
        location = request.form.get('location')
        comments = Comment(username=session['username'], text=comment, location=location)
        db.session.add(comments)
        db.session.commit()
        return redirect("/books/read/" + location)
    else:
        return render_template('alert.html', message="You can't make comment via this route, please find a specific page or post to make comment to.")

@app.route('/rating', methods=['GET', 'POST'])
@login_required
@verification_required
def rating():
    if request.method == 'POST':
        if not request.form.get('rating'):
            return render_template('alert.html', message='Make sure you filled out all required field(s)!')
        rating = request.form.get('rating')
        location = request.form.get('location')
        ratingDb = Book.query.filter_by(title=location).first()
        if ratingDb.rating == "No rating":
            ratingDb.rating = rating
            db.session.commit()
            return render_template('success.html', message='success rating')
        else:
            ratingInDb = float(ratingDb.rating)
            newRating = (ratingInDb + float(rating)) / 2;
            ratingDb.rating = newRating
            db.session.commit()
            return render_template('success.html', message='success rating', link="/books/read/" + location)
    else:
        return render_template('alert.html', message='None')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/profile/username', methods=['POST'])
def change_username():
    email = session['email']
    new_username = request.form.get('new_username')
    user = User.query.filter_by(email=email).first()
    user.username = new_username
    email = user.email
    db.session.commit()
    session['username'] = new_username
    send_email(email, "IMPORTANT: YOUR USERNAME CHANGED", "Hello, your account at https://boyuanliu6.pythonanywhere.com has just changed its USERNAME.")
    return render_template('success.html', message='username changed success.')

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
    send_email(email, "IMPORTANT: YOUR PASSWORD CHANGED", "Hello, your account at https://boyuanliu6.pythonanywhere.com has just changed its password.")
    return render_template('success.html', message='password changed success.')

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
    send_email(new_email, "Verify your Saltie Nation Account!", "Click following link to access " + "https://boyuanliu6.pythonanywhere.com/verification/" + verificationCode)
    send_email(new_email, "IMPORTANT: YOUR EMAIL CHANGED", "Hello, your account at https://boyuanliu6.pythonanywhere.com has just changed its email address.")
    return render_template('success.html', message="Email changed success, check your email for verification.")

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

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/google2cea6360674968aa.html')
def google_site_verification():
    return render_template('google2cea6360674968aa.html')

google_blueprint = make_google_blueprint(client_id='18763142059-1ujrgntne9mrimdi9cu2rg69hfjtqt3k.apps.googleusercontent.com', client_secret='yZ2Jm66hECA6cW42TaHXEmp9', scope=['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'openid'])
app.register_blueprint(google_blueprint, url_prefix='/google_login')

@app.route('/google')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get("/oauth2/v1/userinfo")
    assert resp.ok, resp.text
    return redirect('/')

@app.route('/term')
def term():
    return render_template('term.html')

@oauth_authorized.connect_via(google_blueprint)
def google_authorized(blueprint, token):
    resp = google.get("/oauth2/v1/userinfo")
    assert resp.ok, resp.text
    email = resp.json()['email']
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
            return redirect('/')
    except AttributeError:
        pass
    registrant = User(email=email, username=email, password="(Google)", status="user")
    db.session.add(registrant)
    db.session.commit()
    userAfter = User.query.filter_by(email=email).first()
    session["user_id"] = userAfter.id
    session["username"] = email
    session['status'] = userAfter.status
    session['email'] = email
    session['verification'] = 'verified'
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