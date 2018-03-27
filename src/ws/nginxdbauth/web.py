from flask import Flask, request
import argparse
import os
import os.path
import sqlalchemy
import sys
import wsgiref.handlers
import wsgiref.simple_server

try:
    from ConfigParser import ConfigParser
except ImportError:
    from configparser import ConfigParser

app = Flask(__name__)


@app.route('/')
def auth_view():
    config = ConfigParser()
    config.read(os.path.expanduser(os.environ['NGINXDBAUTH_CONFIG']))
    get = lambda x: config.get('default', x)  # noqa
    db = sqlalchemy.create_engine(get('dsn'))
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
    found = len(db.execute(sqlalchemy.text(get('query')), **params).fetchall())
    if found == 1:
        return 'OK', 200
    return 'FAIL', 403


@app.errorhandler(Exception)
def handle_error(error):
    return str(error), 500


def cgi():
    # We only have the one route
    os.environ['PATH_INFO'] = '/'
    wsgiref.handlers.CGIHandler().run(app.wsgi_app)


def serve():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='localhost', help='bind host')
    parser.add_argument('--port', default='8899', help='bind port', type=int)
    parser.add_argument('--config', help='path to config file')
    options = parser.parse_args()
    if options.config:  # auth_view will raise KeyError to signal missing param
        os.environ['NGINXDBAUTH_CONFIG'] = options.config
    wsgiref.simple_server.make_server(
        options.host, options.port, app.wsgi_app).serve_forever()
