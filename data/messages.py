import sqlalchemy
from .db_session import SqlAlchemyBase
from binascii import hexlify


class Message(SqlAlchemyBase):
    __tablename__ = "messages"

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    data = sqlalchemy.Column(sqlalchemy.String)
    chat_id = sqlalchemy.Column(sqlalchemy.String)
    sent_by = sqlalchemy.Column(sqlalchemy.String)
    type = sqlalchemy.Column(sqlalchemy.Integer)
    viewed = sqlalchemy.Column(sqlalchemy.Boolean)
    server = sqlalchemy.Column(sqlalchemy.Boolean)
    unix_time = sqlalchemy.Column(sqlalchemy.Integer)
    key = sqlalchemy.Column(sqlalchemy.String)
    signature = sqlalchemy.Column(sqlalchemy.String)

    def __init__(self, data, type, viewed, chat_id, sent_by, row=None, unix_time=2147483647, key=None, signature=None):
        self.data = data
        self.type = type
        self.viewed = viewed
        self.sent_by = sent_by
        self.chat_id = chat_id
        self.unix_time = unix_time
        self.row = row
        self.key = key
        self.signature = signature

    def __eq__(self, other):
        return round(self.unix_time) == round(other.unix_time) and self.chat_id == other.chat_id

    def __hash__(self):
        return int(hexlify(f"""{round(self.unix_time)}{self.chat_id}""".encode("utf-8")), 16)

    def __repr__(self):
        return f"Message(data: {self.data}, type: {self.type}, viewed: {self.viewed}, chat_id: {self.chat_id}, sent_by: {self.sent_by}, unix_time: {self.unix_time})"
