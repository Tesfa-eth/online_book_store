import sqlite3
from flask import Flask, render_template, request, url_for, flash, redirect
from werkzeug.exceptions import abort

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yoursecretkey' # should always be located bellow app definition and def index
# Remember that the secret key should be a long random string.

@app.route('/')
def index():
    """render index html"""
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)