import sqlalchemy
from .db_session import SqlAlchemyBase
from binascii import hexlify


class Message(SqlAlchemyBase):
    __tablename__ = "messages"

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    data = sqlalchemy.Column(sqlalchemy.String)
    name = sqlalchemy.Column(sqlalchemy.String)
    chat_id = sqlalchemy.Column(sqlalchemy.String)
    sended_by = sqlalchemy.Column(sqlalchemy.String)
    type = sqlalchemy.Column(sqlalchemy.Integer)
    viewed = sqlalchemy.Column(sqlalchemy.Boolean)
    unix_time = sqlalchemy.Column(sqlalchemy.Integer)

    def __init__(self, data, type, viewed, chat_id, sended_by, name, row=None):
        self.data = data
        self.type = type
        self.viewed = viewed
        self.unix_time = unix_time
        self.sended_by = sended_by
        self.name = name
        self.chat_id = chat_id
        self.row_id = row_id

    def __eq__(self, other):
        return self.data == other.data and self.type == other.type and\
            self.unix_time == other.unix_time and self.name == other.name and\
            self.chat_id == other.chat_id and self.sended_by == other.sended_by

    def __hash__(self):
        return int(hexlify(f"""{self.data}{self.type}
                               {self.unix_time}{self.name}
                               {self.chat_id}{self.sended_by}""".encode("utf-8")), 16)

    def __str__(self):
        return f"Message(data: {self.data}, type: {self.type}, viewed: {self.viewed}, chat_id: {self.chat_id}, sended_by: {self.sended_by}, name: {self.name}, unix_time: {self.unix_time})"
