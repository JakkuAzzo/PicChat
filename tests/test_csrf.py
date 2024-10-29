import pytest
from flask import Flask, render_template_string, session, request
from flask_wtf.csrf import CSRFProtect
from bs4 import BeautifulSoup
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadData

@pytest.fixture
def app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret!'
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['TESTING'] = True

    # Initialize CSRF protection
    csrf = CSRFProtect(app)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            return 'Logged in', 200
        return render_template_string('''
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <input type="submit">
            </form>
        ''')

    return app

def test_csrf_token(app):
    client = app.test_client()

    # Get the login page to retrieve the CSRF token
    response = client.get('/login')
    assert response.status_code == 200

    # Parse the HTML response to extract the CSRF token
    soup = BeautifulSoup(response.data, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']

    # Make a POST request with the CSRF token
    response = client.post('/login', data={'csrf_token': csrf_token})
    assert response.status_code == 200
    assert b'Logged in' in response.data

    # Test a POST request without the CSRF token to ensure CSRF protection is enforced
    response = client.post('/login')
    assert response.status_code == 400  # 400 Bad Request indicates CSRF protection failure

def test_csrf_token_in_query_string(app):
    client = app.test_client()

    # Get the login page to retrieve the CSRF token
    response = client.get('/login')
    assert response.status_code == 200

    # Parse the HTML response to extract the CSRF token
    soup = BeautifulSoup(response.data, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']

    # Make a POST request with the CSRF token in query string
    response = client.post('/login', query_string={'csrf_token': csrf_token})
    assert response.status_code == 200

def test_csrf_token_disabled(app):
    app.config['WTF_CSRF_ENABLED'] = False
    client = app.test_client()

    # Get the login page to retrieve the CSRF token
    response = client.get('/login')
    assert response.status_code == 200

    # Make a POST request without the CSRF token
    response = client.post('/login')
    assert response.status_code == 200
    assert b'Logged in' in response.data

def test_expired_csrf_token(app):
    client = app.test_client()

    # Get the login page to retrieve the CSRF token
    response = client.get('/login')
    assert response.status_code == 200

    # Parse the HTML response to extract the CSRF token
    soup = BeautifulSoup(response.data, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']

    # Manually expire the CSRF token
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt="wtf-csrf-token")
    expired_token = s.dumps({'csrf_token': csrf_token})
    expired_token = expired_token.split('.')[0] + '.expired'

    # Make a POST request with the expired CSRF token
    response = client.post('/login', data={'csrf_token': expired_token})
    assert response.status_code == 400  # 400 Bad Request indicates CSRF protection failure

def test_csrf_token_with_ssl_strict(app):
    app.config['WTF_CSRF_SSL_STRICT'] = True
    client = app.test_client()

    # Get the login page to retrieve the CSRF token
    response = client.get('/login')
    assert response.status_code == 200

    # Parse the HTML response to extract the CSRF token
    soup = BeautifulSoup(response.data, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']

    # Make a POST request with the CSRF token
    response = client.post('/login', data={'csrf_token': csrf_token}, base_url='https://localhost')
    assert response.status_code == 200
    assert b'Logged in' in response.data

    # Test a POST request without the CSRF token to ensure CSRF protection is enforced
    response = client.post('/login', base_url='https://localhost')
    assert response.status_code == 400  # 400 Bad Request indicates CSRF protection failure

def test_csrf_token_with_ssl_strict_invalid_referrer(app):
    app.config['WTF_CSRF_SSL_STRICT'] = True
    client = app.test_client()

    # Get the login page to retrieve the CSRF token
    response = client.get('/login')
    assert response.status_code == 200

    # Parse the HTML response to extract the CSRF token
    soup = BeautifulSoup(response.data, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']

    # Make a POST request with the CSRF token and invalid referrer
    response = client.post('/login', data={'csrf_token': csrf_token}, headers={'Referer': 'https://invalid.com'})
    assert response.status_code == 400  # 400 Bad Request indicates CSRF protection failure