# coding: utf8
import base64
import os
import passlib.context
import pytest
import sqlalchemy
import ws.nginxdbauth.web


@pytest.fixture
def database(tmpdir):
    db = sqlalchemy.create_engine('sqlite:////%s' % tmpdir.join('auth.db'))
    db.execute(
        'CREATE TABLE users ('
        'id integer, username varchar(40), password varchar(40), '
        'role varchar(40))')
    db.execute('INSERT INTO users VALUES (1, "normal", "asdf", "normal")')
    db.execute('INSERT INTO users VALUES (2, "super", "qwer", "super")')
    return db


@pytest.fixture
def config(monkeypatch):
    os.environ['NGINXDBAUTH_CONFIG'] = '/dev/null'

    def inner(config):
        monkeypatch.setattr('ws.nginxdbauth.web.ConfigParser.get',
                            lambda self, s, x: config.get(x))
        monkeypatch.setattr('ws.nginxdbauth.web.ConfigParser.has_option',
                            lambda self, s, x: x in config)
    return inner


def basic_auth(username, password):
    return {'Authorization': 'Basic '.encode('ascii') + base64.b64encode(
        u':'.join([username, password]).encode('latin1'))}


def test_correct_password_returns_200(config, database):
    config({'dsn': database.url, 'query': 'SELECT id FROM users WHERE '
            'username = :username AND password = :password'})
    b = ws.nginxdbauth.web.app.test_client()
    r = b.get('/', headers=basic_auth('normal', 'asdf'))
    assert r.status_code == 200, r.data.decode('ascii')


def test_wrong_password_returns_403(config, database):
    config({'dsn': database.url, 'query': 'SELECT id FROM users WHERE '
            'username = :username AND password = :password'})
    b = ws.nginxdbauth.web.app.test_client()
    r = b.get('/', headers=basic_auth('normal', 'invalid'))
    assert r.status_code == 403, r.data.decode('ascii')


def test_headers_are_available_as_query_parameters(config, database):
    config({
        'dsn': database.url, 'query': 'SELECT id FROM users WHERE '
        'username = :username AND password = :password AND role = :x_role'})
    b = ws.nginxdbauth.web.app.test_client()
    headers = basic_auth('super', 'qwer')
    headers['X-Role'] = 'super'
    r = b.get('/', headers=headers)
    assert r.status_code == 200, r.data.decode('ascii')

    headers = basic_auth('normal', 'asdf')
    headers['X-Role'] = 'super'
    r = b.get('/', headers=headers)
    assert r.status_code == 403, r.data.decode('ascii')


def test_handles_non_ascii_entries(config, database):
    database.execute(u'INSERT INTO users VALUES (3, "ümläut", "asdf", "")')
    config({'dsn': database.url, 'query': 'SELECT id FROM users WHERE '
            'username = :username AND password = :password'})
    b = ws.nginxdbauth.web.app.test_client()
    r = b.get('/', headers=basic_auth(u'ümläut', 'asdf'))
    assert r.status_code == 200, r.data.decode('ascii')


def test_password_hashing_with_passlib(config, database):
    pwd_context = passlib.context.CryptContext(schemes=['sha256_crypt'])
    database.execute('INSERT INTO users VALUES (3, "foo", :pw, "")',
                     pw=pwd_context.hash('secret'))
    config({'dsn': database.url,
            'query': 'SELECT password FROM users WHERE username = :username',
            'password_hash': 'sha256_crypt'})
    b = ws.nginxdbauth.web.app.test_client()
    r = b.get('/', headers=basic_auth('foo', 'secret'))
    assert r.status_code == 200, r.data.decode('ascii')


def test_no_auth_header_returns_401(config):
    b = ws.nginxdbauth.web.app.test_client()
    r = b.get('/')
    assert r.status_code == 401, r.data.encode('ascii')
    r = b.get('/', headers={'WWW-Authenticate': 'my realm'})
    assert r.status_code == 401, r.data.encode('ascii')
    assert r.headers['WWW-Authenticate'] == 'my realm'
