from flask_sqlalchemy import SQLAlchemy

"""
    Here we manage our sqlite3 database using SQLAlchemy.
"""

_DB = SQLAlchemy()


def init_db(app):
    with app.app_context():
        _DB.init_app(app)
        _DB.create_all()


def write_db():
    _DB.session.commit()

def get_db():
    return _DB



class rules(_DB.Model):
    id = _DB.Column(_DB.Integer, primary_key=True)
    active = _DB.Column(_DB.Boolean, unique=False, nullable=False)
    name = _DB.Column(_DB.String(80), unique=True, nullable=False)
    direction = _DB.Column(_DB.Integer, unique=False, nullable=False)
    rule_type = _DB.Column(_DB.Integer, unique=False, nullable=False)
    rule = _DB.Column(_DB.JSON, unique=False, nullable=False)
