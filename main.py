from flask import Flask, request, redirect, render_template, session
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://blogz@localhost:8889/blogz'
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)
app.secret_key = 'cj2r)$xj&sthqc=6o1v@pts4plq^c8t=r0qw^uwqvr%u%2r8ed'


class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    heading = db.Column(db.String(120))
    content = db.Column(db.String(1000))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self,heading,content,user):
        self.heading = heading
        self.content = content
        self.user = user


class User(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(100),unique=True)
    password = db.Column(db.String(100))
    posts = db.relationship('Blog', backref='user')

    def __init__(self,email,password):
        self.email = email
        self.password = password

    def __repr__(self):
        return self.email


def validate_email(email):

    email_error = ''

    if email == "":
        email_error = "Email address required"
        return email_error
    if " " in email:
        email_error = "Email address cannot contain whitespace"
        return email_error
    if len(email) >= 100:
        email_error = "Email must be between 3 - 100 Characters"
        return email_error
    if len(email) <= 3:
        email_error = "Email must be between 3 - 100 Characters"
        return email_error
    if '@' not in email:
        email_error = "Email address requires '@' symbol"
        return email_error
    if '.' not in email:
        email_error = "Email address requires '.' symbol"
        return email_error
    else:
        return ''


def validate_pw(password, password_check=''):

    password_error = ''
    password_check_error = ''

    if len(password) == 0 and len(password_check) == 0:
        password_error = "Password required"
        return password_error
    if len(password) > 100 or len(password) < 3:
        password_error = "Password must be between 3 - 100 Characters"
        return password_error
    if " " in password:
        password_error = "Password must not contain whitespace"
        return password_error 
    if password_check and password != password_check:
        password_error = "Passwords must match"
        return password_error
    else:
        return ''


def validate_title(heading):

    heading_error = ''

    if len(heading) > 120:
        heading_error = "Title must be under 120 characters"
        return heading_error
    if len(heading) == 0:
        heading_error = "Title required"
        return heading_error
    else:
        return ''


def validate_content(content):

    content_error = ''

    if len(content) > 250:
        content_error = "Content must be under 1000 characters"
        return content_error
    if len(content) == 0:
        content_error = "Content required"
        return content_error
    else:
        return ''


@app.before_request
def require_login():
    allowed_routes = ['login','signup','index','main_page']
    if request.endpoint not in allowed_routes and 'email' not in session:
        return redirect('/login')


@app.route('/', methods=['GET'])
def index():
    users = User.query.all()
    user = request.args.get('user')
    if user:
        posts = Blog.query.all()
        return render_template('usersPage.html',tab_title="Blog", posts=posts)
    else:
        return render_template('index.html',tab_title="Blog", users=users)


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        password_check = request.form['password_check']
        email_error = validate_email(email)
        password_error = validate_pw(password, password_check)
        user_exists_error = 'User already exists'

        existing_user = User.query.filter_by(email=email).first()
        if not email_error and not password_error:
            if not existing_user:
                new_user = User(email, password)
                db.session.add(new_user)
                db.session.commit()
                session['email'] = email
                return redirect('/')
            else:
                return render_template('signup.html',tab_title="Signup (post)",
                                        email = email,user_exists_error=user_exists_error)
        else:
            return render_template('signup.html',tab_title="Signup (post)",email_error = email_error, email = email, 
                                    password_error = password_error)
    else:
        if request.method == 'GET':
            return render_template('signup.html',tab_title="Signup (get)")


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        email_error = validate_email(email)
        password_error = validate_pw(password)
        login_error = "User does not exist"
        
        if not email_error and not password_error:
            user = User.query.filter_by(email=email).first()
            if user and user.password == password:
                session['email'] = email
                return redirect('/')
            else:
                return render_template('login.html',tab_title="Log In",email=email,login_error=login_error)
        else:
            return render_template('login.html',tab_title="Log In",email_error = email_error, email = email,
                                    password_error = password_error)
    if request.method == 'GET':
        return render_template('login.html',tab_title="Log In")


@app.route('/blog', methods=['GET'])
def main_page():
    posts = Blog.query.all()
    all_emails = User.query.all()
    user = request.args.get('user')
    blog_id = request.args.get('id')
    
    if blog_id != None:
        entry = Blog.query.get(blog_id)
        user_obj = User.query.filter_by(id=entry.user_id).first() 
        return render_template('single_entry.html', tab_title="All Blogs (blog_id)", entry=entry, user=user_obj)

    if user == None:
        posts = Blog.query.all()
        return render_template('blog.html', tab_title='All Blogs (user))', posts=posts)
    
    else:
        user_obj = User.query.filter_by(email=user).first()
        posts = Blog.query.filter_by(user_id=user_obj.id).all()
        return render_template('blog.html',tab_title='All Blogs (get)',
                                posts=posts, user=user_obj)

    return render_template('blog.html',tab_title='All Blogs (last get)',posts=posts)


@app.route('/new_entry', methods=['POST','GET'])
def validate_submit_new_entry():

    if request.method == 'POST':
        heading = request.form['heading']
        content = request.form['content']
        heading_error = validate_title(heading)
        content_error = validate_content(content)
        
        if heading_error or content_error:
            return render_template('new_entry.html',tab_title="New Entry",
            heading_error=heading_error,content_error=content_error)
        
        else:
            user = User.query.filter_by(email=session['email']).first()
            new_entry = Blog(heading,content,user)
            db.session.add(new_entry)
            db.session.commit()
            query_post = "/blog?id=" + str(new_entry.id)
            return redirect(query_post)

    else:
        if request.method == 'GET':
            return render_template('new_entry.html',tab_title="New Entry")


@app.route('/logout')
def logout():
    del session['email']
    return redirect('/')


if __name__ == '__main__':
    app.run()