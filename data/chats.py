import sqlalchemy
from .db_session import SqlAlchemyBase


class Chat(SqlAlchemyBase):
    __tablename__ = "chats"

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    username = sqlalchemy.Column(sqlalchemy.String, unique=True)
    chat_id = sqlalchemy.Column(sqlalchemy.String, unique=True)
    last_message = sqlalchemy.Column(sqlalchemy.String)
    unix_time = sqlalchemy.Column(sqlalchemy.Integer)

    def __init__(self, username, chat_id, last_message, unix_time):
        self.username = username
        self.chat_id = chat_id
        self.last_message = last_message
        self.unix_time = unix_time

    def __eq__(self, other):
        return self.chat_id == other.chat_id and\
            self.unix_time == other.unix_time
