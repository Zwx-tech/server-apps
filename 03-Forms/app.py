# importowanie modułów i klas
from flask import Flask, render_template, redirect, session
from flask_bs4 import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

# konfiguracja aplikacji
app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = 'dfghjvbn%^&*tyugh^&*(YHJ%^&*GHJ&*' # klucz szyfrowania danych z formularza

# formularz logowania
class LoginForm(FlaskForm):
    """formularz logowania"""
    userLogin = StringField('Nazwa użytkownika:', validators=[DataRequired()])
    userPass = PasswordField('Hasło:', validators=[DataRequired()])
    submit = SubmitField('Zaloguj')

users = {
    'userLogin': 'lblitek',
    'userPass': 'Qwerty123!',
    'firstName': 'Łukasz',
    'lastName': 'Blitek'
}

# główna część aplikacji
@app.route('/')
def index():
    return render_template('index.html', title='Home')

@app.route('/logIn', methods=['POST', 'GET'])
def logIn():
    login = LoginForm()
    if login.validate_on_submit():
        userLogin = login.userLogin.data
        userPass = login.userPass.data
        if userLogin == users['userLogin'] and userPass == users['userPass']:
            session['userLogin'] = userLogin
            return redirect('dashboard')
    return render_template('login.html', title='Logowanie', login=login)

@app.route('/logOut')
def logOut():
    session.pop('userLogin')
    return redirect('logIn')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', title='Dashboard', userLogin=session.get('userLogin'))

@app.errorhandler(404)
def pageNotFound(e):
    return render_template('404.html', title='Page not found'), 404

@app.errorhandler(500)
def serverError(e):
    return render_template('500.html'), 500

# uruchomienie aplikacji
if __name__ == '__main__':
    app.run(debug=True)