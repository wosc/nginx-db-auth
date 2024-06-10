from configparser import ConfigParser
from flask import Flask, request, make_response
from sqlalchemy.orm import Session
import argparse
import logging
import os
import os.path
import sqlalchemy
import sys
import wsgiref.handlers
import wsgiref.simple_server

app = Flask(__name__)

log = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(levelname)-5.5s [%(name)s] %(message)s'

CONFIG = {}
DB = None


def parse_config(filename):
    CONFIG['parsed'] = True
    config = ConfigParser()
    config.read(os.path.expanduser(filename))
    if config.has_section('default'):
        CONFIG.update(config.items('default'))
    return CONFIG


def setup_db(config):
    global DB
    if DB is not None:
        return

    sa_options = {
        key.replace('sqlalchemy.', '', 1): value
        for key, value in config.items() if key.startswith('sqlalchemy.')}
    DB = sqlalchemy.create_engine(config['dsn'], **sa_options)


@app.route('/')
def auth_view():
    if not request.authorization:
        response = make_response('AUTHENTICATE', 401)
        if 'WWW-Authenticate' in request.headers:
            response.headers['WWW-Authenticate'] = request.headers[
                'WWW-Authenticate']
        return response

    if not CONFIG.get('parsed'):
        parse_config(os.environ['NGINXDBAUTH_CONFIG'])
    setup_db(CONFIG)

    params = {
        'username': request.authorization.username,
        'password': request.authorization.password,
    }
    for key, value in request.headers:
        params[key.lower().replace('-', '_')] = value

    verified = False
    with Session(DB) as db:
        result = db.execute(
            sqlalchemy.text(CONFIG['query']), params).fetchall()
    if len(result) == 1:
        hashing = CONFIG.get('password_hash')
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
    log.error('An error occured', exc_info=True)
    return str(error), 500


def cgi():
    # We only have the one route
    os.environ['PATH_INFO'] = '/'
    logfile = os.environ.get('NGINXDBAUTH_LOGFILE')
    if logfile:
        logging.basicConfig(filename=logfile, format=LOG_FORMAT)
    wsgiref.handlers.CGIHandler().run(app.wsgi_app)


def serve():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='localhost', help='bind host')
    parser.add_argument('--port', default='8899', help='bind port', type=int)
    parser.add_argument('--config', help='path to config file (required)')
    options = parser.parse_args()
    if not options.config:
        parser.print_usage()
        sys.exit(1)
    logging.basicConfig(stream=sys.stdout, format=LOG_FORMAT)
    # Work around pyca/bcrypt#684
    logging.getLogger('passlib').setLevel(logging.ERROR)
    config = parse_config(options.config)
    setup_db(config)
    wsgiref.simple_server.make_server(
        options.host, options.port, app.wsgi_app).serve_forever()
