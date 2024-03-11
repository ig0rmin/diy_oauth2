#!/usr/bin/env python
import os
from flask import Flask, render_template, redirect, request, abort
from pymongo import MongoClient
from joserfc import jwt
from dotenv import load_dotenv
import bcrypt
import uuid
import time

app = Flask(__name__)

load_dotenv()

jwt_secret = os.environ.get('JWT_SECRET')
mongo_db_host = os.environ.get('MONGO_DB_HOST')
mongo_db_port = int(os.environ.get('MONGO_DB_PORT'))
client_callback = os.environ.get('CLIENT_CALLBACK')

client = MongoClient(mongo_db_host, mongo_db_port)
db = client['oauth2_demo']
users_collection = db['users']
tokens_collection = db['tokens']

def create_user(user_name, password):
    existing_user = users_collection.find_one({"user_name": user_name})
    if existing_user:
        raise Exception("User already exists")

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    user_doc = {
        "user_name": user_name,
        "password": hashed_password
    }
    result = users_collection.insert_one(user_doc)
    return result.inserted_id

def check_password(user_name, password):
    user = users_collection.find_one({"user_name": user_name})
    if not user:
        raise Exception("User not found")

    if not bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        raise Exception("Incorrect password")

    return user["_id"]

def issue_authorization_token(user_name, password):
    user_id = check_password(user_name, password)
    token = str(uuid.uuid4())
    expiration_time = time.time() + 1200
    token_doc = {
        "user_id": user_id,
        "token": token,
        "expiration_time": expiration_time
    }
    tokens_collection.insert_one(token_doc)
    return token

def consume_authorization_token(token):
    token_doc = tokens_collection.find_one({"token": token})
    if not token_doc:
        return None
    tokens_collection.delete_one({"token": token})
    if token_doc["expiration_time"] < time.time():
       return None
    return str(token_doc['user_id'])

def issue_jwt_token(user_id):
    return jwt.encode({'alg':'HS256'}, {'user_id':user_id}, jwt_secret)

@app.route('/', methods=['GET'])
def home():
   return redirect('/oauth/authorize')

# For test purposes only
@app.route('/create_user', methods=['POST'])
def create_user_route():
    if not request.is_json:
        abort(400, "Request body should have JSON")
    data = request.get_json()
    user_name = data['username']
    password = data['password']
    if user_name is None or password is None:
        abort(400, "Bad request")
    try:
        user_id = create_user(user_name, password)
        return f'User created: {user_id}'
    except Exception as e:
        abort(409, str(e))

# Should authorize the user and on success issue authorization token
@app.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'POST':
        user_name = request.form.get('username')
        password = request.form.get('password')
        try:
            user_id = check_password(user_name, password)
        except Exception:
           abort(401, "Unauthorized") 
        token = issue_authorization_token(user_name, password) 
        return redirect(f'/oauth/token?token={token}')
    return render_template('authorize.html')

# Exchenage authorization token to the JWT access token
@app.route('/oauth/token', methods=['GET'])
def access_token():
    token = request.args.get('token')
    if token is not None:
        user_id = consume_authorization_token(token)
        if user_id is not None:
            jwt_token = issue_jwt_token(user_id)
            return redirect(f'{client_callback}?token={jwt_token}')
    abort(401, "Unauthorized")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)