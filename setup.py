"""Authenticate an nginx request against an SQL database."""
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import glob


setup(
    name='ws.nginxdbauth',
    version='1.0.5.dev0',

    install_requires=[
        'flask',
        'setuptools',
        'sqlalchemy>=2.0.0',
        'Flask-SQLAlchemy',
    ],

    extras_require={
        'test': [
            'passlib',
            'pytest-cov',
        ],
    },

    entry_points={
        'console_scripts': [
            'nginx-db-auth-cgi = ws.nginxdbauth.web:cgi',
            'nginx-db-auth-serve = ws.nginxdbauth.web:serve',
        ],
    },

    author='Wolfgang Schnerring <wosc@wosc.de>',
    author_email='wosc@wosc.de',
    license='ZPL 2.1',
    url='https://github.com/wosc/nginx-db-auth',

    description=__doc__.strip(),
    long_description='\n\n'.join(open(name).read() for name in (
        'README.rst',
        'CHANGES.txt',
    )),

    classifiers="""\
License :: OSI Approved :: Zope Public License
Programming Language :: Python
Programming Language :: Python :: 2
Programming Language :: Python :: 2.7
Programming Language :: Python :: 3
Programming Language :: Python :: 3.4
Programming Language :: Python :: 3.5
Programming Language :: Python :: 3.6
Programming Language :: Python :: Implementation :: CPython
"""[:-1].split('\n'),

    namespace_packages=['ws'],
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    data_files=[('', glob.glob('*.txt'))],
    zip_safe=False,
)
