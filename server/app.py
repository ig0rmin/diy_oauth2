#!/usr/bin/env python
from flask import Flask, render_template, redirect, request
from pymongo import MongoClient

app = Flask(__name__)

client = MongoClient('mongodb', 27017)
db = client['statistics']
collection = db['counter']

@app.route('/', methods=['GET'])
def home():
   return redirect('/oauth/authorize')

# Should authorize the user and on success issue authorization token
@app.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        return render_template('showpassword.html', username=username, password=password)
    return render_template('authorize.html')

# Exchenage authorization token to the JWT access token
@app.route('/oauth/token', methods=['POST'])
def issue_token():
    pass

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)