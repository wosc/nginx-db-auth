# coding: utf8
from sqlalchemy import text
import base64
import os
import passlib.context
import pytest
import sqlalchemy
import ws.nginxdbauth.web


@pytest.fixture
def database(tmpdir):
    if ws.nginxdbauth.web.DB is not None:
        ws.nginxdbauth.web.DB.dispose()
        ws.nginxdbauth.web.DB = None

    db = sqlalchemy.create_engine('sqlite:////%s' % tmpdir.join('auth.db'))
    conn = db.connect()
    conn.execute(text(
        'CREATE TABLE users ('
        'id integer, username varchar(40), password varchar(40), '
        'role varchar(40))'))
    conn.execute(
        text('INSERT INTO users VALUES (1, "normal", "asdf", "normal")'))
    conn.execute(
        text('INSERT INTO users VALUES (2, "super", "qwer", "super")'))
    conn.commit()
    conn.url = db.url
    return conn


@pytest.fixture
def config(monkeypatch):
    ws.nginxdbauth.web.CONFIG.clear()
    os.environ['NGINXDBAUTH_CONFIG'] = '/dev/null'

    def inner(config):
        monkeypatch.setattr('ws.nginxdbauth.web.ConfigParser.has_section',
                            lambda self, s: True)
        monkeypatch.setattr('ws.nginxdbauth.web.ConfigParser.items',
                            lambda self, s: config.items())
    return inner


def basic_auth(username, password):
    return {'Authorization': 'Basic '.encode('ascii') + base64.b64encode(
        ':'.join([username, password]).encode('utf-8'))}


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
    database.execute(text(
        'INSERT INTO users VALUES (3, "ümläut", "asdf", "")'))
    database.commit()
    config({'dsn': database.url, 'query': 'SELECT id FROM users WHERE '
            'username = :username AND password = :password'})
    b = ws.nginxdbauth.web.app.test_client()
    r = b.get('/', headers=basic_auth('ümläut', 'asdf'))
    assert r.status_code == 200, r.data.decode('ascii')


def test_password_hashing_with_passlib(config, database):
    pwd_context = passlib.context.CryptContext(schemes=['sha256_crypt'])
    database.execute(text('INSERT INTO users VALUES (3, "foo", :pw, "")'),
                     dict(pw=pwd_context.hash('secret')))
    database.commit()
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
