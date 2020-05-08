import sqlalchemy
from .db_session import SqlAlchemyBase
from binascii import hexlify


class User(SqlAlchemyBase):
    __tablename__ = "users"
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    username = sqlalchemy.Column(sqlalchemy.String, unique=True)
    public_key = sqlalchemy.Column(sqlalchemy.String)
