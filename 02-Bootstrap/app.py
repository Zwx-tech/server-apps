# importowanie modułów i klas
from flask import Flask, render_template
from flask_bs4 import Bootstrap

# konfiguracja aplikacji
app = Flask(__name__)
bootstrap = Bootstrap(app)

# główna część aplikacji
@app.route('/')
def index():
    return render_template('index.html', title='Home')

@app.errorhandler(404)
def pageNotFound(e):
    return render_template('404.html', title='Page not found'), 404

@app.errorhandler(500)
def serverError(e):
    return render_template('500.html'), 500

# uruchomienie aplikacji
if __name__ == '__main__':
    app.run(debug=True)