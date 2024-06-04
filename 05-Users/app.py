from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from sqlalchemy.orm import relationship
from wtforms import StringField, PasswordField, SubmitField, EmailField, SelectField, FileField
from wtforms.fields.simple import HiddenField
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
app.config['UPLOAD_EXTENSIONS'] = ['jpg', 'jpeg', 'png', 'txt']
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
    folderName = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    icon = db.Column(db.String(50), nullable=False)
    time = db.Column(db.String(50), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=True)
    path_to_folder = db.Column(db.String(255), nullable=True)

    parent = relationship('Folders', remote_side=[id], back_populates='subfolders')
    subfolders = relationship('Folders', back_populates='parent', cascade='all, delete-orphan')
    files = relationship('Files', back_populates='folder', cascade='all, delete-orphan')

class Files(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fileName = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    icon = db.Column(db.String(50), nullable=False)
    size = db.Column(db.Float, nullable=False)
    time = db.Column(db.String(50), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=True)

    folder = relationship('Folders', back_populates='files')

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
    parentId = HiddenField('Parent Folder')
    submit = SubmitField('Utwórz')

class UploadFiles(FlaskForm):
    """formularz przesyłania plików"""
    fileName = FileField('Plik', validators=[FileAllowed(app.config['UPLOAD_EXTENSIONS'])], render_kw={'placeholder': '.jpg, .jpeg, .png, .txt'})
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

@app.route('/dashboard', defaults={'folder_id': None})
@app.route('/dashboard/<int:folder_id>')
@login_required
def dashboard(folder_id):
    print(f"dashborad: {folder_id}")
    addUser = Add()
    editUser = Edit()
    editUserPass = ChangePass()
    search = Search()
    createFolder = CreateFolders()
    uploadFile = UploadFiles()

    allUsers = Users.query.all()
    current_folder = Folders.query.get(folder_id) if folder_id else ''
    parent_folder = current_folder.parent_id if current_folder else False
    id = folder_id if folder_id else None
    folders = db.session.query(Folders).filter(Folders.parent_id == id).all()
    print(list(map(lambda x: x.parent_id, db.session.query(Folders).all())))
    print(db.session.query(Folders).filter(Folders.parent_id == '').all())
    files = Files.query.filter_by(folder_id=folder_id).all()

    return render_template('dashboard.html', title='Dashboard', allUsers=allUsers, addUser=addUser,
                           editUser=editUser, editUserPass=editUserPass, search=search, createFolder=createFolder,
                           uploadFile=uploadFile, current_folder=id, folders=folders, files=files, parent_folder=parent_folder)

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

@app.route('/create-folder/', defaults={'folder_id': None}, methods=['GET', 'POST'])
@app.route('/create-folder/<string:folder_id>', methods=['GET', 'POST'])
@login_required
def create_folder(folder_id):
    form = CreateFolders()
    print(f"create_folder: {folder_id}")
    if form.validate_on_submit():
        folder_name = form.folderName.data
        parent_id = folder_id

        parent_folder = Folders.query.get(parent_id) if parent_id else None
        path_to_folder = parent_folder.path_to_folder if parent_id else ''
        parent_path = os.path.join(app.config['UPLOAD_PATH'], path_to_folder)
        relative_path = os.path.join(path_to_folder, folder_name)
        folder_path = os.path.join(parent_path, folder_name)

        os.makedirs(folder_path, exist_ok=True)

        time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        new_folder = Folders(folderName=folder_name, type='folder', icon='bi bi-folder', time=time, parent_id=parent_id, path_to_folder=relative_path)
        db.session.add(new_folder)
        db.session.commit()

        flash('Folder utworzony poprawnie', 'success')
        return redirect(url_for('dashboard',  folder_id=parent_id))
    return redirect(url_for('dashboard'))

@app.route('/rename-folder', methods=['GET', 'POST'])
@login_required
def renameFolder():
    return redirect(url_for('dashboard'))

@app.route('/delete-folder/', defaults={'folder_id': None}, methods=['GET', 'POST'])
@app.route('/delete-folder/<string:folder_id>', methods=['GET', 'POST'])
@login_required
def deleteFolder(folder_id):
    print(f"deleteFolder: {folder_id}")
    folder = Folders.query.get(folder_id)
    parent_id = folder.parent_id
    os.removedirs(os.path.join(app.config['UPLOAD_PATH'], folder.path_to_folder))
    db.session.delete(folder)
    db.session.commit()
    return redirect(url_for('dashboard', folder_id=parent_id))

@app.route('/upload-file/', defaults={'folder_id': None}, methods=['GET', 'POST'])
@app.route('/upload-file/<string:folder_id>', methods=['GET', 'POST'])
@login_required
def upload_file(folder_id):
    form = UploadFiles()
    print("FILEUPLOAD", folder_id, form.validate_on_submit())
    if not form.validate_on_submit(): return redirect(url_for('dashboard'))

    uploaded_file = form.fileName.data
    file_name = secure_filename(uploaded_file.filename)
    print("FILENAME!!!!\n", file_name)
    parent_id = folder_id
    print("PARENT ID", parent_id)
    parent_folder = Folders.query.get(int(parent_id)) if folder_id else None
    print("PARENT FOLDER", parent_folder)
    path_to_folder = parent_folder.path_to_folder if folder_id else ''
    file_path = os.path.join(app.config['UPLOAD_PATH'], path_to_folder, file_name)

    print("FILEPATH!!!!\n", file_path)
    file_extension = os.path.splitext(file_name)[1]
    # if file_extension not in app.config['UPLOAD_EXTENSIONS']:
    #     abort(400)

    uploaded_file.save(file_path)

    type = file_extension[1:]  # Strip the dot
    icon = f'bi bi-filetype-{type}'

    time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    size = round(os.stat(file_path).st_size / (1024 * 1024), 2)
    new_file = Files(fileName=file_name, type=type, icon=icon, size=size, time=time, folder_id=int(folder_id) if folder_id else None)
    db.session.add(new_file)
    db.session.commit()

    flash('Plik przesłany poprawnie', 'success')
    return redirect(url_for('dashboard', folder_id=folder_id))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

# https://zsl514.fls.jetbrains.com