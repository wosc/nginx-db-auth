"""web.py."""
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import os.path
import sys

import wsgiref.handlers
import wsgiref.simple_server

from flask import Flask, request, make_response
from flask_sqlalchemy import SQLAlchemy

try:
    from ConfigParser import ConfigParser
except ImportError:
    from configparser import ConfigParser

app = Flask(__name__)
log = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(levelname)-5.5s [%(name)s] %(message)s'
db = SQLAlchemy()
config = ConfigParser()
get = (
    lambda x: config.get('default', x)
    if config.has_option('default', x) else None
)


def _setup():
    config.read(os.path.expanduser(os.environ['NGINXDBAUTH_CONFIG']))
    app.config['SQLALCHEMY_DATABASE_URI'] = get('dsn')
    app.config['SQLALCHEMY_POOL_RECYCLE'] = 280
    db.init_app(app)


@app.route('/')
def auth_view():
    """auth_view."""
    if not request.authorization:
        response = make_response('AUTHENTICATE', 401)
        if 'WWW-Authenticate' in request.headers:
            response.headers['WWW-Authenticate'] = request.headers[
                'WWW-Authenticate']
        return response
    params = {
        'username': request.authorization.username,
        'password': request.authorization.password,
    }
    if sys.version_info < (3,):
        # XXX Werkzeug bug, authorization properties should be unicode already.
        for key, value in list(params.items()):
            params[key] = value.decode('latin1')
    for key, value in request.headers:
        params[key.lower().replace('-', '_')] = value

    verified = False
    result = db.session.execute(
        db.text(get('query')),
        params,
    ).fetchall()
    if len(result) == 1:
        hashing = get('password_hash')
        if hashing:
            import passlib.context  # soft dependency
            pwd_context = passlib.context.CryptContext(schemes=[hashing])
            verified = pwd_context.verify(params['password'], result[0][0])
        else:
            verified = True
    if verified:
        return 'OK', 200
    else:
        return 'FAIL', 403


@app.errorhandler(Exception)
def handle_error(error):
    """handle_error.

    Args:
        error: error
    """
    log.error('An error occured', exc_info=True)
    return str(error), 500


def cgi():
    """cgi."""
    # We only have the one route
    os.environ['PATH_INFO'] = '/'
    logfile = os.environ.get('NGINXDBAUTH_LOGFILE')
    if logfile:
        logging.basicConfig(filename=logfile, format=LOG_FORMAT)
    _setup()
    wsgiref.handlers.CGIHandler().run(app.wsgi_app)


def serve():
    """serve."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='localhost', help='bind host')
    parser.add_argument('--port', default='8899', help='bind port', type=int)
    parser.add_argument('--config', help='path to config file')
    options = parser.parse_args()
    if options.config:  # auth_view will raise KeyError to signal missing param
        os.environ['NGINXDBAUTH_CONFIG'] = options.config
    logging.basicConfig(stream=sys.stdout, format=LOG_FORMAT)
    _setup()
    wsgiref.simple_server.make_server(
        options.host,
        options.port,
        app.wsgi_app,
    ).serve_forever()
