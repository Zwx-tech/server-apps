# pip install flask flask_sqlalchemy flask_login flask_wtf wtforms flask_wtf werkzeug flask_bcrypt flask_bs4
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, SelectField, FileField
from wtforms.validators import DataRequired, Length
from flask_wtf.file import FileAllowed
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_bs4 import Bootstrap
import os
from datetime import datetime

# konfiguracja aplikacji
app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = 'kjhgf6789THJKLOI*(*&O'
bcrypt = Bcrypt(app)
app.config['UPLOAD_PATH'] = 'uploads'
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.jpeg', '.png', '.txt']
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16MB

# konfiguracja bazy danych
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data/users.sqlite')
db = SQLAlchemy(app)

# tabela w bazie danych
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(20))
    lastName = db.Column(db.String(30))
    userMail = db.Column(db.String(50), unique=True)
    userPass = db.Column(db.String(50))
    userRole = db.Column(db.String(20))

    def is_authenticated(self):
        return True

class Folders(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    folderName = db.Column(db.String(50), unique=True)
    type = db.Column(db.String(20))
    icon = db.Column(db.String(20))
    time = db.Column(db.String(20))
    folderPath = db.Column(db.String(200))

class Files(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fileName = db.Column(db.String(50), unique=True)
    type = db.Column(db.String(20))
    icon = db.Column(db.String(20))
    time = db.Column(db.String(20))
    size = db.Column(db.String(20))

# konfiguracja Flask-Login
loginManager = LoginManager()
loginManager.init_app(app)
loginManager.login_view = 'login'
loginManager.login_message = 'Nie jesteś zalogowany'
loginManager.login_message_category = 'warning'

@loginManager.user_loader
def loadUser(id):
    return Users.query.filter_by(id=id).first()

# fomularze
class Register(FlaskForm):
    """formularz rejestracji użytkowników"""
    firstName = StringField('Imię', validators=[DataRequired()], render_kw={"placeholder": 'Imię'})
    lastName = StringField('Nazwisko', validators=[DataRequired()], render_kw={"placeholder": 'Nazwisko'})
    userMail = EmailField('Mail', validators=[DataRequired()], render_kw={"placeholder": 'Mail'})
    userPass = PasswordField('Hasło', validators=[DataRequired()], render_kw={"placeholder": 'Hasło'})
    submit = SubmitField('Rejestruj')

class Login(FlaskForm):
    """formularz logowania użytkowników"""
    userMail = EmailField('Mail', validators=[DataRequired()], render_kw={"placeholder": 'Mail'})
    userPass = PasswordField('Hasło', validators=[DataRequired()], render_kw={"placeholder": 'Hasło'})
    submit = SubmitField('Zaloguj')

class Add(FlaskForm):
    """formularz dodawania użytkowników"""
    firstName = StringField('Imię', validators=[DataRequired()], render_kw={"placeholder": 'Imię'})
    lastName = StringField('Nazwisko', validators=[DataRequired()], render_kw={"placeholder": 'Nazwisko'})
    userMail = EmailField('Mail', validators=[DataRequired()], render_kw={"placeholder": 'Mail'})
    userPass = PasswordField('Hasło', validators=[DataRequired()], render_kw={"placeholder": 'Hasło'})
    userRole = SelectField('Uprawnienia', validators=[DataRequired()], choices=[('user', 'Użytkownika'), ('admin', 'Administrator')])
    submit = SubmitField('Dodaj')

class Edit(FlaskForm):
    """formularz rejestracji użytkowników"""
    firstName = StringField('Imię', validators=[DataRequired()], render_kw={"placeholder": 'Imię'})
    lastName = StringField('Nazwisko', validators=[DataRequired()], render_kw={"placeholder": 'Nazwisko'})
    userMail = EmailField('Mail', validators=[DataRequired()], render_kw={"placeholder": 'Mail'})
    userRole = SelectField('Uprawnienia', validators=[DataRequired()], choices=[('user', 'Użytkownika'), ('admin', 'Administrator')])
    submit = SubmitField('Zapisz')

class Password(FlaskForm):
    """formularz do zmiany hasła przez użytkownika"""
    userMail = EmailField('Mail:', validators=[DataRequired(), Length(min=3, max=50)], render_kw={"placeholder": "Mail", "readonly": True})
    userPass = PasswordField('Bieżące hasło:', validators=[DataRequired(), Length(min=3, max=50)], render_kw={"placeholder": "Bieżące hasło"})
    newUserPass = PasswordField('Nowe hasło:', validators=[DataRequired(), Length(min=3, max=50)], render_kw={"placeholder": "Nowe hasło"})
    submit = SubmitField('Zapisz')

class ChangePass(FlaskForm):
    """formularz do zmiany hasła użytkownika z panelu admina"""
    userPass = PasswordField('Hasło', validators=[DataRequired()], render_kw={"placeholder": 'Hasło'})
    submit = SubmitField('Zapisz')

class Search(FlaskForm):
    """fomularz wyszukiwania plików lub folderów"""
    searchKey = StringField('Szukaj', validators=[DataRequired()])
    submit = SubmitField('Szukaj')

class CreateFolders(FlaskForm):
    """formularz tworzenia folderów"""
    folderName = StringField('Nazwa folderu', validators=[DataRequired()], render_kw={'placeholder': 'Nazwa folderu'})
    submit = SubmitField('Utwórz')

class UploadFiles(FlaskForm):
    """formularz przesyłania plików"""
    fileName = FileField('Plik', validators=[FileAllowed([app.config['UPLOAD_EXTENSIONS']])], render_kw={'placeholder': '.jpg, .jpeg, .png, .txt'})
    submit = SubmitField('Prześlij')

@app.route('/register', methods=['GET', 'POST'])
def register():
    register = Register()
    user = Users.query.all()
    if register.validate_on_submit() and not user:
        try:
            hashPass = bcrypt.generate_password_hash(register.userPass.data)
            newUser = Users(
                firstName=register.firstName.data,
                lastName=register.lastName.data,
                userMail=register.userMail.data,
                userPass=hashPass, userRole='admin'
            )
            db.session.add(newUser)
            db.session.commit()
            flash('Konto utworzone poprawnie', 'success')
            return redirect(url_for('login'))
        except Exception:
            flash('Adres email istniej. Proszę podać inny', 'danger')
    elif register.validate_on_submit():
        try:
            hashPass = bcrypt.generate_password_hash(register.userPass.data)
            newUser = Users(
                firstName=register.firstName.data,
                lastName=register.lastName.data,
                userMail=register.userMail.data,
                userPass=hashPass, userRole='user'
            )
            db.session.add(newUser)
            db.session.commit()
            flash('Konto utworzone poprawnie', 'success')
            return redirect(url_for('login'))
        except Exception:
            flash('Adres email istniej. Proszę podać inny', 'danger')
    return render_template('register.html', title='Logowanie', headline='Rejestracja', register=register)

@app.route('/login', methods=['GET', 'POST'])
def login():
    user = Users.query.all()
    if not user:
        return redirect(url_for('register'))
    else:
        login = Login()
        if login.validate_on_submit():
            user = Users.query.filter_by(userMail=login.userMail.data).first()
            if user:
                if bcrypt.check_password_hash(user.userPass, login.userPass.data):
                    login_user(user)
                    return redirect(url_for('dashboard'))
    return render_template('login.html', title='Logowanie', headline = 'Logowanie', login=login)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# główna aplikacji
@app.route('/')
def index():
    return render_template('index.html', title = 'Home', headline = 'Zarządzanie użytkownikami')

@app.route('/dashboard<path:string>')
@login_required
def dashboard(path):
    if not path:
        path = ''
    addUser = Add()
    editUser = Edit()
    editUserPass = ChangePass()
    search = Search()
    createFolder = CreateFolders()
    uploadFile = UploadFiles()
    allUsers = Users.query.all()

    # Get the absolute path of the directory the user is viewing
    abs_path = os.path.join(app.config['UPLOAD_PATH'], path)

    # Get the folders and files in the current directory
    folders = [f for f in os.listdir(abs_path) if os.path.isdir(os.path.join(abs_path, f))]
    files = [f for f in os.listdir(abs_path) if os.path.isfile(os.path.join(abs_path, f))]

    return render_template('dashboard.html', title='Dashboard', allUsers=allUsers, addUser=addUser, editUser=editUser,
                           editUserPass=editUserPass, search=search, createFolder=createFolder, uploadFile=uploadFile,
                           folders=folders, files=files, path=path)

@app.route('/addUser', methods=['POST', 'GET'])
@login_required
def addUser():
    addUser = Add()
    if addUser.validate_on_submit():
        try:
            hashPass = bcrypt.generate_password_hash(addUser.userPass.data)
            newUser = Users(userMail=addUser.userMail.data, userPass=hashPass, firstName=addUser.firstName.data, lastName=addUser.lastName.data, userRole=addUser.userRole.data)
            db.session.add(newUser)
            db.session.commit()
            flash('Konto utworzone poprawnie', 'success')
            return redirect(url_for('dashboard'))
        except Exception:
            flash('Taki adres mail istnieje, wpisz inny', 'danger')
            return redirect(url_for('dashboard'))

@app.route('/edit-user<int:id>', methods=['POST', 'GET'])
@login_required
def editUser(id):
    editUser = Edit()
    user = Users.query.get_or_404(id)
    if editUser.validate_on_submit():
        user.firstName = editUser.firstName.data
        user.lastName = editUser.lastName.data
        user.userMail = editUser.userMail.data
        user.userRole = editUser.userRole.data
        db.session.commit()
        flash('Dane zapisane poprawnie', 'success')
        return redirect(url_for('dashboard'))

@app.route('/deleteUser', methods=['POST', 'GET'])
@login_required
def deleteUser():
    if request.method == 'GET':
        id = request.args.get('id')
        user = Users.query.filter_by(id=id).first()
        db.session.delete(user)
        db.session.commit()
        flash('Użytkownik usunięty poprawnie', 'success')
        return redirect(url_for('dashboard'))

@app.route('/change-pass', methods=['GET', 'POST'])
@login_required
def changePass():
    changePassForm = Password()
    if changePassForm.validate_on_submit():
        user = Users.query.filter_by(userMail=changePassForm.userMail.data).first()
        if user:
            if bcrypt.check_password_hash(user.userPass, changePassForm.userPass.data):
                user.userPass = bcrypt.generate_password_hash(changePassForm.newUserPass.data)
                db.session.commit()
                flash('Hasło zostało zmienione', 'success')
                return redirect(url_for('dashboard'))
    return render_template('change-pass.html', title='Zmiana hasła', changePassForm=changePassForm)

@app.route('/edit-user-pass<int:id>', methods=['GET', 'POST'])
@login_required
def editUserPass(id):
    editUserPass = ChangePass()
    user = Users.query.get_or_404(id)
    if editUserPass.validate_on_submit():
        user.userPass = bcrypt.generate_password_hash(editUserPass.userPass.data)
        db.session.commit()
        flash('Hasło zostało zmienione', 'success')
        return redirect(url_for('dashboard'))

@app.route('/create-folder/<path:current_path>', methods=['GET', 'POST'])
@login_required
def createFolder(current_path):
    folderName = request.form['folderName']
    if folderName != '':
        # Create the folder inside the current directory
        folderPath = os.path.join(app.config['UPLOAD_PATH'], current_path, folderName)
        os.makedirs(folderPath, exist_ok=True)
        time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        newFolder = Folders(folderName=folderName, folderPath=folderPath, type='folder', icon='bi bi-folder', time=time)
        db.session.add(newFolder)
        db.session.commit()
        flash('Folder utworzony poprawnie', 'success')
        return redirect(url_for('dashboard', path=current_path))

@app.route('/rename-folder', methods=['GET', 'POST'])
@login_required
def renameFolder():
    return redirect(url_for('dashboard'))

@app.route('/delete-folder', methods=['GET', 'POST'])
@login_required
def deleteFolder():
    return redirect(url_for('dashboard'))

@app.route('/upload-file', methods=['GET', 'POST'])
@login_required
def uploadFile():
    uploadedFile = request.files['fileName']
    fileName = secure_filename(uploadedFile.filename)
    if fileName != '':
        fileExtension = os.path.splitext(fileName)[1]
        if fileExtension not in app.config['UPLOAD_EXTENSIONS']:
            abort(400)
        type = ''
        icon = ''
        if fileExtension == '.png':
            type = 'png'
            icon = 'bi bi-filetype-png'
        elif fileExtension == '.jpg':
            type = 'jpg'
            icon = 'bi bi-filetype-jpg'
        elif fileExtension == '.jpeg':
            type = 'jpeg'
            icon = 'bi bi-filetype-jpg'
        elif fileExtension == '.txt':
            type = 'txt'
            icon = 'bi bi-filetype-txt'
        uploadedFile.save(os.path.join(app.config['UPLOAD_PATH'], fileName))
        time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        size = round(os.stat(os.path.join(app.config['UPLOAD_PATH'], fileName)).st_size / (1024 * 1024), 2)
        newFile = Files(fileName=fileName, type=type, icon=icon, size=size, time=time)
        db.session.add(newFile)
        db.session.commit()
        flash('Plik przesłany poprawnie', 'success')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

# https://zsl514.fls.jetbrains.com