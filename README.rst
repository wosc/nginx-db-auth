=============================================
nginx basic authentication against a database
=============================================

This packages answers an `nginx auth subrequest`_ by looking up the
user/password in a database (mysql, postgresql, whatever `sqlalchemy`_
supports).

.. _`nginx auth subrequest`: https://nginx.org/en/docs/http/ngx_http_auth_request_module.html
.. _`sqlalchemy`: http://www.sqlalchemy.org/


Usage
=====

Configure database access
-------------------------

You'll need to provide the DSN and the query using a configuration file::

    [default]
    dsn = sqlite:///path/to/auth.db
    query = SELECT id FROM users WHERE username = :username AND password = :password AND role = :x_required_role

See the `sqlalchemy documentation`_ for supported DSNs. Note that you have to
install the respective driver python package (``mysql-python``, ``psycopg2``,
etc.) yourself.

.. _`sqlalchemy documentation`: http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls

The query gets passed as SQL parameters the basic auth ``username`` and
``password`` as well as any request headers (lowercase, and ``-`` replaced
with ``_``). (If that is not flexible enough for your usecase, you'll have to
run separate instances with specialized queries, for the time being).



Set up HTTP service
-------------------

Then you need to set up an HTTP server, either with a dedicated process::

    $ nginx-db-auth-serve --host localhost --port 8899 --config /path/to/config

or as a CGI script, if you have infrastructure for that set up anyway.
Here's an example apache configuration snippet to do this::

    ScriptAlias /nginx-auth /path/to/nginxdbauth/nginx-db-auth-cgi
    <Location /nginx-auth>
      SetEnv NGINXDBAUTH_CONFIG /path/to/config
    </Location>


Configure nginx
---------------

Now you can set up a protected nginx location like this::

        location /private/ {
            auth_request /auth;
            # ... define rest of location ...
        }

        location = /auth {
            proxy_pass http://localhost:8899;  # or http://mycgi/nginx-auth
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Required-Role "superuser";
        }

