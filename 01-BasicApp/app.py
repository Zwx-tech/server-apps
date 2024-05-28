# importowanie modułów i klas
from flask import Flask, render_template

# konfiguracja aplikacji
app = Flask(__name__)

# główna część aplikacji
@app.route('/')
def index():
    return ('<h1>Hello</h1>')

@app.route('/template')
def template():
    return render_template('index.html', title='Templates')

@app.route('/users/<userName>')
def users(userName):
    return render_template('users.html', title='Użytkownicy', userName=userName)

# uruchomienie aplikacji
if __name__ == '__main__':
    app.run(debug=True)