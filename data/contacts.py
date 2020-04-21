import sqlalchemy
from .db_session import SqlAlchemyBase


class Contact(SqlAlchemyBase):
    __tablename__ = "contacts"

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    username = sqlalchemy.Column(sqlalchemy.String, unique=True)
    readable_name = sqlalchemy.Column(sqlalchemy.String)
    picture = sqlalchemy.Column(sqlalchemy.String)

    def __init__(self, username, readable_name, picture):
        self.username = username
        self.readable_name = readable_name
        self.picture = picture

    def __eq__(self, other):
        if type(other) == str:
            return self.username == other
        else:
            return self.username == other.username
