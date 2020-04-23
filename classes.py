from rocket import MessageTypes


class TextMessage:
    def __init__(self, text, username):
        self.text = text
        self.username = username
        self.type = MessageTypes.Text

    def __eq__(self, other):
        return self.text == other.text and self.username == other.username and self.type == other.type
