from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from Data import Data
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, fields
from passlib.hash import sha256_crypt

app = Flask(__name__)

# Config MySQL

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'PythonFlask'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Initialize MySQL

mysql = MySQL(app)

# Profile Data Integration
Data = Data()


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/profile')
def profile():
    return render_template('profile.html', data=Data)


@app.route('/profiles/<string:id>/')
def profiles(id):
    return render_template('profiles.html', id=id)


class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('User Name', [validators.Length(min=4, max=25)])
    email = StringField('EMAIL', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        usr_nme = form.username.data
        paswrd = sha256_crypt.encrypt(str(form.password.data))

        # Create Cursor

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name, email, usr_nme, paswrd) VALUES(%s, %s, %s, %s)", (name, email, usr_nme, paswrd))

        # Committing the Query

        mysql.connection.commit()

        # Close Connection

        cur.close()

        flash(name + ' Registered Successfully ', 'success')
        form.name.data = ""
        form.email.data = ""
        form.username.data = ""

        redirect(url_for('login'))

    return render_template('register.html', form=form)

# User Login


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form fields
        username = request.form['username']
        pass_emp = request.form['password']

        # Create Cursor
        cur = mysql.connection.cursor()

        # Finding User by User Name
        result = cur.execute("SELECT * FROM users WHERE usr_nme = %s", [username])
        if result > 0:
            # Get Stored Value
            data = cur.fetchone()
            password = data['paswrd']

            # Compare Passwords
            if sha256_crypt.verify(pass_emp, password):
                # app.logger.info('Password Matched')
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid User Name or Password'
                return render_template('login.html', error=error)
            # Connection Closed
            cur.close()
        else:
            error = 'User Name not found'
            return render_template('login.html', error=error)

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.secret_key = 'secret123'
    port = 8000  # the custom port you want
    app.run(host='127.0.0.1', port=port, debug=True)


