#!/usr/bin/env python
from flask import Flask, request, session, abort, render_template, redirect
from joserfc import jwt
from joserfc.errors import BadSignatureError

app = Flask(__name__)
app.secret_key = 'secret'

jwt_secret = 'jwt secret'

def validate_jwt(jwt):
    try:
        decoded = jwt.decode(jwt, jwt_secret)
        return decoded.claims
    except BadSignatureError: 
        return {}

def user_info(user_id):
    return "<p>User id: {user_id}</p>".format(user_id)

def check_auth(request):
    """Check that user is authorized.

    Returns:
        User ID.
    """
    auth_header = request.headers.get('Authorization')

    request_token = None
    if auth_header and auth_header.startswith('Bearer '):
        request_token = auth_header.split(' ')[1]

    session_token = None
    if 'token' in session:
        session_token = session['token']

    # Token from request takes priority over session
    if request_token is not None:
        claims = validate_jwt(request_token)
        if 'user' in claims:
            session['token'] = request_token
            return claims['user']
        else:
            del session['b']
            return None
    
    if session_token is not None:
        claims = validate_jwt(session_token)
        if 'user' in claims:
            return claims['user']

    return None

@app.route('/', methods=['GET', 'POST'])
def home():
    user_id = check_auth(request)
    if user_id is None:
        if request.method == 'GET':
            return render_template('unauthorized.html')
        else:
            return redirect('http://localhost:8081/oauth/authorize')
    return render_template('userinfo.html', user_id=user_id)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)