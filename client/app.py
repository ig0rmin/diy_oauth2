from flask import Flask, request, session, abort, render_template, redirect
from joserfc import jwt
from joserfc.errors import BadSignatureError

app = Flask(__name__)
app.secret_key = 'secret'

jwt_secret = 'jwt secret'

def validate_jwt(token):
    try:
        decoded = jwt.decode(token, jwt_secret)
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
    request_token = request.args.get('token')

    session_token = None
    if 'token' in session:
        session_token = session['token']
    else:
        app.logger.debug('token not in the session')

    # Token from request takes priority over session
    if request_token is not None:
        claims = validate_jwt(request_token)
        if 'user_id' in claims:
            session['token'] = request_token
            return claims['user_id']
        else:
            del session['token']
            return None
    
    if session_token is not None:
        claims = validate_jwt(session_token)
        if 'user_id' in claims:
            return claims['user_id']
    else:
        app.logger.debug('Session token is None')

    return None

@app.route('/callback', methods=['GET'])
def callback():
    user_id = check_auth(request)
    if user_id is not None:
        return redirect('/')
    abort(401, "Unauthorized")

@app.route('/', methods=['GET', 'POST'])
def home():
    user_id = check_auth(request)
    if user_id is None:
        if request.method == 'GET':
            return render_template('unauthorized.html')
        else:
            return redirect('http://localhost:8081/oauth/authorize')
    return render_template('userinfo.html', user_id=user_id)

@app.route('/logout', methods=['POST'])
def logout():
    del session['token']
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)