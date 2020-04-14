from PyQt5 import QtWidgets, QtCore, QtGui
from threading import Thread
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import hashlib
import requests
from rocket import RocketAPI, RocketAPIThread, MessageTypes
from collections import namedtuple
import asyncio
import json


regular_font = QtGui.QFont("fonts/Roboto-Regular.ttf")
bold_font = QtGui.QFont("fonts/Roboto-Black.ttf")
Chat = namedtuple("Chat", ["username", "image", "chat_id"])
try:
    credentials = json.load(open("credentials.json", encoding="utf-8"))
except FileNotFoundError:
    with open("credentials.json", "w", encoding="utf-8") as f:
        f.write("{}")


def password_check(passwd):
    val = True
    err_text = None

    if len(passwd) < 8:
        err_text = 'length should be at least 8'
        val = False

    if not any(char.isdigit() for char in passwd):
        err_text = 'Password should have at least one numeral'
        val = False

    if not any(char.isupper() for char in passwd):
        err_text = 'Password should have at least one uppercase letter'
        val = False

    if not any(char.islower() for char in passwd):
        err_text = 'Password should have at least one lowercase letter'
        val = False

    return val, err_text


class TextMessage:
    def __init__(self, text, username):
        self.text = text
        self.username = username
        self.type = MessageTypes.Text


class Chat:
    def __init__(self, username, image, chat_id):
        self.username = username
        self.image = image
        self.chat_id = chat_id


class GrowingTextEdit(QtWidgets.QTextEdit):
    def __init__(self, *args, **kwargs):
        super(GrowingTextEdit, self).__init__(*args, **kwargs)  
        self.document().contentsChanged.connect(self.sizeChange)

        self.heightMin = 0
        self.heightMax = 120

    def sizeChange(self):
        docHeight = self.document().size().height()
        if self.heightMin <= docHeight <= self.heightMax:
            self.setMinimumHeight(docHeight)


class SigninWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent=parent)

        self.resize(590, 500)
        self.parent = parent

        self.centralwidget = QtWidgets.QWidget(self)
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)

        logo_box = QtWidgets.QGroupBox()
        self.logo_label = QtWidgets.QLabel(self.centralwidget)
        self.logo_label.setAlignment(QtCore.Qt.AlignCenter)
        pixmap = QtGui.QPixmap("img/rocket128.png")
        self.logo_label.setPixmap(pixmap)
        self.name_label = QtWidgets.QLabel("Rocket Sender")
        self.name_label.setAlignment(QtCore.Qt.AlignCenter)
        bold_font.setPointSize(28)
        self.name_label.setFont(bold_font)
        vbox = QtWidgets.QVBoxLayout()
        vbox.addWidget(self.logo_label)
        vbox.addWidget(self.name_label)
        vbox.setAlignment(QtCore.Qt.AlignTop)
        logo_box.setLayout(vbox)
        regular_font.setPointSize(14)
        self.login_line = QtWidgets.QLineEdit(self.centralwidget)
        self.login_line.setPlaceholderText("Login")
        self.login_line.setFont(regular_font)
        self.password_line = QtWidgets.QLineEdit(self.centralwidget)
        self.password_line.setPlaceholderText("Password")
        self.password_line.setFont(regular_font)
        self.password_line.setEchoMode(QtWidgets.QLineEdit.Password)
        self.signin_button = QtWidgets.QPushButton(self.centralwidget)
        self.signin_button.setText("Sign in")
        self.signin_button.setFont(regular_font)
        self.signin_button.clicked.connect(self.signin)
        self.signup_button = QtWidgets.QPushButton(self.centralwidget)
        self.signup_button.setText("Sign up")
        self.signup_button.setFont(regular_font)
        self.signup_button.clicked.connect(SignupWindow(self).show)

        self.signin_thread = RocketAPIThread()
        self.signin_thread.signal.connect(self.signin_finished)

        self.gridLayout.addWidget(QtWidgets.QLabel(), 0, 0, 1, 4)
        self.gridLayout.addWidget(logo_box, 1, 0, 1, 4)
        self.gridLayout.addWidget(self.login_line, 3, 1, 1, 2)
        self.gridLayout.addWidget(self.password_line, 4, 1, 1, 2)
        self.gridLayout.addWidget(self.signin_button, 5, 1, 1, 2)
        self.gridLayout.addWidget(self.signup_button, 6, 1, 1, 2)
        self.gridLayout.addWidget(QtWidgets.QLabel(), 7, 0, 1, 4)

        self.setCentralWidget(self.centralwidget)

    def signin_finished(self, response):
        login = self.login_line.text()
        password = self.password_line.text()
        if response["status"] == "OK":
            with open("credentials.json", "w", encoding="utf-8") as f:
                response["data"]["login"] = login
                response["data"]["password"] = password
                json.dump(response["data"], f)
            ChatsWindow().show()
            self.close()
        else:
            QtWidgets.QMessageBox.critical(self, "", response["error"])

    def signin(self):
        login = self.login_line.text()
        password = self.password_line.text()
        if login != "" and password != "":
            self.signin_thread.function = RocketAPI.get_user_data
            self.signin_thread.args = [login, password]
            self.signin_thread.start()
        else:
            QtWidgets.QMessageBox.critical(self, "", "Fill all lines")


class SignupWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.parent = parent

        self.resize(590, 500)
        self.centralwidget = QtWidgets.QWidget(self)
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.setWindowModality(QtCore.Qt.ApplicationModal)

        logo_box = QtWidgets.QGroupBox()
        self.logo_label = QtWidgets.QLabel(self.centralwidget)
        self.logo_label.setAlignment(QtCore.Qt.AlignCenter)
        pixmap = QtGui.QPixmap("img/rocket128.png")
        self.logo_label.setPixmap(pixmap)
        self.name_label = QtWidgets.QLabel("Rocket Sender")
        self.name_label.setAlignment(QtCore.Qt.AlignCenter)
        bold_font.setPointSize(28)
        self.name_label.setFont(bold_font)
        vbox = QtWidgets.QVBoxLayout()
        vbox.addWidget(self.logo_label)
        vbox.addWidget(self.name_label)
        vbox.setAlignment(QtCore.Qt.AlignTop)
        logo_box.setLayout(vbox)
        regular_font.setPointSize(14)
        self.email_line = QtWidgets.QLineEdit(self.centralwidget)
        self.email_line.setPlaceholderText("Email")
        self.email_line.setFont(regular_font)
        self.login_line = QtWidgets.QLineEdit(self.centralwidget)
        self.login_line.setPlaceholderText("Login")
        self.login_line.setFont(regular_font)
        self.password_line = QtWidgets.QLineEdit(self.centralwidget)
        self.password_line.setPlaceholderText("Password")
        self.password_line.setFont(regular_font)
        self.password_line.setEchoMode(QtWidgets.QLineEdit.Password)
        self.second_password_line = QtWidgets.QLineEdit(self.centralwidget)
        self.second_password_line.setPlaceholderText("Enter password again")
        self.second_password_line.setFont(regular_font)
        self.second_password_line.setEchoMode(QtWidgets.QLineEdit.Password)
        self.second_password_line.sizePolicy().setHorizontalStretch(1)

        self.signup_button = QtWidgets.QPushButton(self.centralwidget)
        self.signup_button.setText("Sign up")
        self.signup_button.setFont(regular_font)
        self.signup_button.clicked.connect(self.initiate_signup)
        self.error_label = QtWidgets.QLabel()
        self.error_label.setStyleSheet("color: red")
        self.error_label.setFont(regular_font)

        self.initiate_signup_thread = RocketAPIThread()
        self.initiate_signup_thread.function = RocketAPI.initiate_signup
        self.initiate_signup_thread.signal.connect(self.initiate_signup_finished)

        self.gridLayout.addWidget(QtWidgets.QLabel(), 0, 0, 1, 4)
        self.gridLayout.addWidget(logo_box, 1, 0, 1, 4)
        self.gridLayout.addWidget(self.email_line, 3, 1, 1, 2)
        self.gridLayout.addWidget(self.login_line, 4, 1, 1, 2)
        self.gridLayout.addWidget(self.password_line, 5, 1, 1, 2)
        self.gridLayout.addWidget(self.second_password_line, 6, 1, 1, 2)
        self.gridLayout.addWidget(self.signup_button, 7, 1, 1, 2)
        self.gridLayout.addWidget(QtWidgets.QLabel(), 8, 0, 1, 4)

        self.setCentralWidget(self.centralwidget)

    def initiate_signup_finished(self, response):
        if response["status"] == "OK":
            TokenWindow(self).show()
        else:
            QtWidgets.QMessageBox().critical(self, "", response["error"])

    def initiate_signup(self):
        password_status, error = password_check(self.password_line.text())
        if self.password_line.text() == "" or\
                self.second_password_line.text() == "" or self.email_line.text() == "":
            QtWidgets.QMessageBox().critical(self, "", "Fill all lines")
        else:
            if self.password_line.text() == self.second_password_line.text():
                if password_status:
                    self.initiate_signup_thread.args = [self.email_line.text()]
                    self.initiate_signup_thread.start()
                else:
                    QtWidgets.QMessageBox().critical(self, "", error)
            else:
                QtWidgets.QMessageBox().critical(self, "", "Passwords don't match")
        self.repaint()


class TokenWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.parent = parent
        self.setWindowModality(QtCore.Qt.ApplicationModal)

        self.setFixedSize(300, 130)
        self.centralwidget = QtWidgets.QWidget(self)
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.counter = 60
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.timeout)
        self.timer.start(1000)
        regular_font.setPointSize(14)
        self.timer_label = QtWidgets.QLabel(self.centralwidget)
        self.timer_label.setStyleSheet("color: gray")
        self.timer_label.setText("Token expires in " + str(self.counter) + " sec.")
        self.timer_label.setFont(regular_font)

        self.label = QtWidgets.QLabel("Enter token from email:")
        self.label.setFont(regular_font)
        self.token_line = QtWidgets.QLineEdit(self.centralwidget)
        self.token_line.setMaxLength(7)
        self.token_line.setPlaceholderText("Token")
        self.token_line.setValidator(QtGui.QIntValidator(0, 9999999))
        self.token_line.setFont(regular_font)
        self.ok_button = QtWidgets.QPushButton(self.centralwidget)
        self.ok_button.setText("Ok")
        self.ok_button.clicked.connect(self.complete_signup)
        self.ok_button.setFont(regular_font)
        self.cancel_button = QtWidgets.QPushButton(self.centralwidget)
        self.cancel_button.setText("Cancel")
        self.cancel_button.clicked.connect(self.close)
        self.cancel_button.setFont(regular_font)
        self.new_token_button = QtWidgets.QPushButton(self.centralwidget)
        self.new_token_button.setText("New token")
        self.new_token_button.setEnabled(False)
        self.new_token_button.clicked.connect(self.new_token)
        self.new_token_button.setFont(regular_font)

        self.initiate_signup_thread = RocketAPIThread()
        self.initiate_signup_thread.function = RocketAPI.initiate_signup
        self.initiate_signup_thread.signal.connect(self.initiate_signup_finished)
        self.complete_signup_thread = RocketAPIThread()
        self.complete_signup_thread.function = RocketAPI.complete_signup
        self.complete_signup_thread.signal.connect(self.complete_signup_finished)
        # self.rocket_thread.signal.connect(self.complete_signup_finished)

        self.gridLayout.addWidget(self.label, 0, 0, 1, 3)
        self.gridLayout.addWidget(self.token_line, 1, 0, 1, 3)
        self.gridLayout.addWidget(self.timer_label, 2, 0, 1, 3)
        self.gridLayout.addWidget(self.ok_button, 3, 1, 1, 1)
        self.gridLayout.addWidget(self.cancel_button, 3, 2, 1, 1)
        self.gridLayout.addWidget(self.new_token_button, 3, 0, 1, 1)

        self.setCentralWidget(self.centralwidget)

    def complete_signup_finished(self, response):
        if response["status"] == "OK":
            self.close()
            self.parent.close()
        else:
            QtWidgets.QMessageBox.critical(self, "", response["error"])

    def initiate_signup_finished(self, response):
        if response["status"] == "OK":
            self.counter = 60
            self.timer.start(1000)
        else:
            QtWidgets.QMessageBox.critical(self, "", response["error"])

    def complete_signup(self):
        email = self.parent.email_line.text()
        password = self.parent.password_line.text()
        token = self.token_line.text()
        login = self.parent.login_line.text()
        hashed_login = hashlib.sha512(login.encode("utf-8")).hexdigest()

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
        )

        with open(hashed_login + ".pem", "wb", encoding="utf-8") as f:
            f.write(private_pem)

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.complete_signup_thread.args = [email, password, 
                                            public_pem.decode("utf-8"),
                                            token, login]
        self.complete_signup_thread.start()

    def timeout(self):
        if self.counter == 0:
            self.new_token_button.setEnabled(True)
            self.timer.stop()
            self.timer_label.setText("Token has expired")
        else:
            self.counter -= 1
            self.timer_label.setText("Token expires in " + str(self.counter) + " sec.")

    def new_token(self):
        self.initiate_signup_thread.args = [self.parent.email_line.text()]
        self.initiate_signup_thread.start()
        self.new_token_button.setEnabled(False)


class ChatsWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.parent = parent

        self.resize(800, 576)
        self.centralwidget = QtWidgets.QWidget(self)
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)

        self.messages_list = QtWidgets.QListWidget(self.centralwidget)
        self.messages_list.setMinimumWidth(350)
        msg = TextMessage(text="Hello, World!", username="@oleg")
        chat_widget = MessageWidget(msg)
        message_item = QtWidgets.QListWidgetItem()
        message_item.setSizeHint(chat_widget.sizeHint())
        self.messages_list.addItem(message_item)
        self.messages_list.setItemWidget(message_item, chat_widget)

        msg = TextMessage(text="Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!vHello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!", username="@vova")
        chat_widget = MessageWidget(msg)
        message_item = QtWidgets.QListWidgetItem()
        message_item.setSizeHint(chat_widget.sizeHint())
        self.messages_list.addItem(message_item)
        self.messages_list.setItemWidget(message_item, chat_widget)

        self.chats_list = QtWidgets.QListWidget(self.centralwidget)
        self.chats_list.setStyleSheet("QListWidget::item { border-bottom: 1px solid lightgray; }")
        self.chats_list.itemClicked.connect(self.chat_selected)
        self.chats_list.setMinimumWidth(270)

        self.obtain_chats = QtCore.QTimer(self)
        self.obtain_chats.timeout.connect(self.timeout)
        self.obtain_chats.start(5000)

        self.loading_label = QtWidgets.QLabel(self)
        self.loading_label.resize(15, 15)
        self.loading_label.setAlignment(QtCore.Qt.AlignCenter)
        self.loading_movie = QtGui.QMovie("img/spinner.gif")
        self.loading_movie.setScaledSize(QtCore.QSize(30, 30))
        self.loading_movie.setCacheMode(QtGui.QMovie.CacheAll)
        self.loading_movie.setSpeed(100)
        self.loading_label.setMovie(self.loading_movie)

        self.create_chat_button = QtWidgets.QPushButton(self.centralwidget)
        self.create_chat_button.setText("Create chat")
        self.create_chat_button.clicked.connect(NewChatWindow(self).show)
        font = regular_font
        font.setPointSize(14)
        self.create_chat_button.setFont(font)

        self.pin_file_button = QtWidgets.QPushButton(self.centralwidget)
        self.pin_file_button.setText("+")
        self.pin_file_button.setFont(font)
        self.message_text_edit = GrowingTextEdit()
        self.message_text_edit.setPlaceholderText("Message")
        self.message_text_edit.setFont(font)
        self.message_text_edit.setMinimumHeight(25)
        self.send_message_button = QtWidgets.QPushButton(self.centralwidget)
        self.send_message_button.setText("Send")
        self.send_message_button.setFont(font)
        self.send_message_button.clicked.connect(self.test)

        self.get_chats_thread = RocketAPIThread()
        self.get_chats_thread.function = RocketAPI.get_user_chats
        self.get_chats_thread.args = [credentials["login"], 
                                      credentials["password"]]
        self.get_chats_thread.signal.connect(self.complete_getting_chats)
        self.loading_movie.start()
        self.get_chats_thread.start()

        self.chats = list()
    
        self.gridLayout.addWidget(self.loading_label, 0, 0, 1, 1, alignment=QtCore.Qt.AlignLeft)
        self.gridLayout.addWidget(self.create_chat_button, 0, 1, 1, 1)
        self.gridLayout.addWidget(self.chats_list, 1, 0, 2, 2, alignment=QtCore.Qt.AlignLeft)
        self.gridLayout.addWidget(self.messages_list, 1, 2, 1, 3)
        self.gridLayout.addWidget(self.pin_file_button, 2, 2, 1, 1)
        self.gridLayout.addWidget(self.message_text_edit, 2, 3, 1, 1, alignment=QtCore.Qt.AlignBottom)
        self.gridLayout.addWidget(self.send_message_button, 2, 4, 1, 1)
        self.gridLayout.setRowStretch(1, 2)
        self.gridLayout.setRowStretch(2, 1)
        self.gridLayout.setSpacing(5)

        self.setCentralWidget(self.centralwidget)

    def chat_selected(self, item):
        chat_widget = self.chats_list.itemWidget(item)
        print(chat_widget.chat.username)

    def test(self):
        self.setCentralWidget(self.centralwidget)

    def timeout(self):
        self.get_chats_thread.start()

    def complete_getting_chats(self, response):
        if response["status"] == "OK":
            self.chats_list.clear()
            for chat in response["chats"]:
                chat_obj = Chat(username=chat["username"], image=None, chat_id=chat["chat_id"])
                chat_widget = ChatWidget(chat_obj)
                chat_item = QtWidgets.QListWidgetItem()
                chat_item.setSizeHint(QtCore.QSize(100, 70))
                self.chats_list.addItem(chat_item)
                self.chats_list.setItemWidget(chat_item, chat_widget)
            self.loading_movie.stop()
            self.loading_label.hide()
        else:
            QtWidgets.QMessageBox().critical(self, "", response["error"])


class ChatWidget(QtWidgets.QWidget):
    def __init__(self, chat):
        super().__init__()
        self.message = "Text"
        self.chat = chat
        vbox = QtWidgets.QGridLayout()
        vbox.setAlignment(QtCore.Qt.AlignLeft)
        user_image_label = QtWidgets.QLabel()
        user_image_label.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        if self.chat.image is None:
            user_image_label.setPixmap(QtGui.QPixmap("img/ghost_user.png").scaled(45, 45, transformMode=QtCore.Qt.SmoothTransformation))
        user_image_label.setAlignment(QtCore.Qt.AlignCenter)
        username_label = QtWidgets.QLabel(self.chat.username)
        bold_font.setPointSize(16)
        username_label.setFont(bold_font)
        message_label = QtWidgets.QLabel(self.message)
        regular_font.setPointSize(12)
        message_label.setFont(regular_font)
        message_label.setStyleSheet("color: gray")
        vbox.setColumnStretch(0, 1)
        vbox.setColumnStretch(1, 5)
        vbox.addWidget(user_image_label, 0, 0, 2, 1)
        vbox.addWidget(username_label, 0, 1, 1, 2)
        vbox.addWidget(message_label, 1, 1, 1, 2)
        vbox.setAlignment(QtCore.Qt.AlignTop)
        self.setLayout(vbox)


class NewChatWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setFixedSize(200, 100)
        regular_font.setPointSize(14)
        self.setWindowModality(QtCore.Qt.ApplicationModal)

        self.centralwidget = QtWidgets.QWidget(self)
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.user_id_line = QtWidgets.QLineEdit(self)
        self.user_id_line.textChanged.connect(self.line_edit_symbol)
        self.user_id_line.setText("@")
        self.user_id_line.setMaxLength(17)
        self.user_id_line.setFont(regular_font)
        self.add_button = QtWidgets.QPushButton(self)
        self.add_button.setText("Create")
        self.add_button.clicked.connect(self.create_chat)
        self.add_button.setFont(regular_font)
        self.cancel_button = QtWidgets.QPushButton(self)
        self.cancel_button.setText("Cancel")
        self.cancel_button.setFont(regular_font)
        self.label = QtWidgets.QLabel("Username:")
        self.label.setFont(regular_font)
        self.gridLayout.addWidget(self.label, 0, 0, 1, 3)
        self.gridLayout.addWidget(self.user_id_line, 1, 0, 1, 3)
        self.gridLayout.addWidget(self.add_button, 2, 2, 1, 1)
        self.gridLayout.addWidget(self.cancel_button, 2, 1, 1, 1)

        self.create_chat_thread = RocketAPIThread()
        self.create_chat_thread.signal.connect(self.finished_creating_chat)

        self.setCentralWidget(self.centralwidget)

    def line_edit_symbol(self):
        if len(self.user_id_line.text()) < 1:
            self.user_id_line.setText("@")

    def finished_creating_chat(self, response):
        if response["status"] == "OK":
            self.close()
        else:
            QtWidgets.QMessageBox().critical(self, " ", response["error"])

    def create_chat(self):
        if len(self.user_id_line.text()) == 17:
            self.create_chat_thread.function = RocketAPI.create_chat
            self.create_chat_thread.args = [credentials["login"],
                                            credentials["password"],
                                            self.user_id_line.text()]
            self.create_chat_thread.start()
        else:
            QtWidgets.QMessageBox().critical(self, " ", "Username should be 9 characters long")

class MessageWidget(QtWidgets.QWidget):
    def __init__(self, message):
        super().__init__()
        self.message = message

        self.gridLayout = QtWidgets.QGridLayout(self)
        self.username_label = QtWidgets.QLabel(self.message.username)
        self.username_label.setStyleSheet("color: blue")
        bold_font.setPointSize(14)
        self.username_label.setFont(bold_font)
        self.message_label = QtWidgets.QLabel()
        self.message_label.setFont(regular_font)
        self.message_label.setText(self.message.text)
        self.message_label.setWordWrap(True)
        self.gridLayout.addWidget(self.username_label, 0, 0, 1, 2, alignment=QtCore.Qt.AlignLeft)
        self.gridLayout.addWidget(self.message_label, 1, 0, 1, 2)
        self.gridLayout.setSpacing(5)
        self.gridLayout.setContentsMargins(11, 5.5, 11, 5.5)
        self.setLayout(self.gridLayout)

if __name__ == "__main__":
    app = QtWidgets.QApplication([""])
    try:
        response = RocketAPI.get_user_data(credentials["login"], credentials["password"])
        if response["status"] == "OK":
            chats_window = ChatsWindow()
            chats_window.show()
        else:
            main = SigninWindow()
            main.show()
    except Exception as e:
        print(e)
        main = SigninWindow()
        main.show()
    app.exec()
