from PyQt5 import QtWidgets, QtCore, QtGui
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from widgets import (ChatWidget, ContactWidget, TextMessageWidget,
                     BottomButtonsBar, GrowingTextEdit, UsernameLineEdit,
                     RoundImageLabel)
from classes import TextMessage
from functions import password_check
from constants import bold_font, regular_font, username_len
from rocket import RocketAPI, RocketAPIThread, MessageTypes
from data import db_session
from data.chats import Chat
from data.contacts import Contact
from data.messages import Message
from threading import Thread
from PIL import Image
import hashlib
import requests
import json
import sqlite3


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
        global api, credentials
        login = self.login_line.text()
        password = self.password_line.text()
        if response["status"] == "OK":
            with open("credentials.json", "w", encoding="utf-8") as f:
                response["data"]["login"] = login
                response["data"]["password"] = password
                json.dump(response["data"], f)
            ChatsWindow().show()
            api = RocketAPI(login, password)
            credentials = json.load(open("credentials.json", "r", encoding="utf-8"))
            self.close()
        else:
            QtWidgets.QMessageBox.critical(self, "", response["error"])

    def signin(self):
        login = self.login_line.text()
        password = self.password_line.text()
        if login != "" and password != "":
            self.signin_thread.function = api.sign_in
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
        self.initiate_signup_thread.function = api.initiate_signup
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
        self.initiate_signup_thread.function = api.initiate_signup
        self.initiate_signup_thread.signal.connect(self.initiate_signup_finished)
        self.complete_signup_thread = RocketAPIThread()
        self.complete_signup_thread.function = api.complete_signup
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

        with open(hashed_login + ".pem", "wb") as f:
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
        self.setStyleSheet("QMainWindow { background-color: white }")
        self.centralwidget = QtWidgets.QWidget(self)
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)

        self.current_chat = None

        self.messages_list = QtWidgets.QListWidget(self.centralwidget)
        # self.messages_list.setMinimumWidth(350)

        self.chats_list = QtWidgets.QListWidget(self.centralwidget)
        self.chats_list.setStyleSheet("QListWidget::item { border-bottom: 1px solid lightgray; }; border: none;")
        self.chats_list.itemClicked.connect(self.chat_selected)
        self.chats_list.setMinimumWidth(270)

        self.contacts_list = QtWidgets.QListWidget(self.centralwidget)
        self.contacts_list.setStyleSheet("QListWidget::item { border-bottom: 1px solid lightgray; }; border: none;")
        self.contacts_list.itemClicked.connect(self.contact_selected)
        self.contacts_list.setMinimumWidth(270)

        self.on_list_label = QtWidgets.QLabel("You have no chats")
        self.on_list_label.setFont(regular_font)
        self.on_list_label.setStyleSheet("color: gray")
        self.on_list_label.setAlignment(QtCore.Qt.AlignCenter)
        self.on_list_label.setMinimumWidth(270)

        self.on_messages_list_label = QtWidgets.QLabel("You have no messages")
        self.on_messages_list_label.setFont(regular_font)
        self.on_messages_list_label.setStyleSheet("color: gray")
        self.on_messages_list_label.setAlignment(QtCore.Qt.AlignCenter)
        self.on_messages_list_label.setText("Select a chat")

        # self.no_chat_selected_label = QtWidgets.QLabel("Select a chat")
        # self.no_chat_selected_label.setFont(regular_font)
        # self.no_chat_selected_label.setStyleSheet("color: gray; border: 1px solid lightgray; background-color: white;")
        # self.no_chat_selected_label.setAlignment(QtCore.Qt.AlignCenter)

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

        self.create_button = QtWidgets.QPushButton(self.centralwidget)
        self.create_button.setText("Create")
        self.create_button.clicked.connect(self.create_button_clicked)
        font = regular_font
        font.setPointSize(14)
        self.create_button.setFont(font)

        self.pin_file_button = QtWidgets.QPushButton(self.centralwidget)
        self.pin_file_button.setText("+")
        self.pin_file_button.setStyleSheet("background-color: white")
        self.message_text_edit = GrowingTextEdit()
        self.message_text_edit.setPlaceholderText("Message")
        self.message_text_edit.setFont(font)
        self.message_text_edit.setMinimumHeight(25)
        self.message_text_edit.setStyleSheet("border: none; background-color: white")
        self.send_message_button = QtWidgets.QPushButton(self.centralwidget)
        self.send_message_button.clicked.connect(self.start_sending_message)
        self.send_message_button.setText("Send")
        self.send_message_button.setFont(font)

        self.buttons_bar = BottomButtonsBar(self)

        self.get_chats_thread = RocketAPIThread()
        self.get_chats_thread.function = api.get_user_chats
        self.get_chats_thread.signal.connect(self.complete_getting_chats)
        self.loading_movie.start()
        self.get_chats_thread.start()

        self.get_messages_thread = RocketAPIThread()
        self.get_messages_thread.function = api.get_all_messages
        self.get_messages_thread.signal.connect(self.complete_getting_messages)

        self.cache_messages_thread = RocketAPIThread()
        self.cache_messages_thread.function = self.cache_messages

        self.chats = session.query(Chat).all()
        self.contacts = session.query(Contact).all()
        self.messages = list()

        self.gridLayout.addWidget(self.loading_label, 0, 0, 1, 1, alignment=QtCore.Qt.AlignLeft)
        self.gridLayout.addWidget(self.create_button, 0, 1, 1, 1)
        self.gridLayout.addWidget(self.chats_list, 1, 0, 1, 2, alignment=QtCore.Qt.AlignLeft)
        self.gridLayout.addWidget(self.contacts_list, 1, 0, 1, 2, alignment=QtCore.Qt.AlignLeft)
        self.gridLayout.addWidget(self.buttons_bar, 2, 0, 1, 2)
        self.gridLayout.addWidget(self.messages_list, 1, 2, 1, 3)
        self.gridLayout.addWidget(self.pin_file_button, 2, 2, 1, 1)
        self.gridLayout.addWidget(self.message_text_edit, 2, 3, 1, 1, alignment=QtCore.Qt.AlignBottom)
        self.gridLayout.addWidget(self.send_message_button, 2, 4, 1, 1)
        self.gridLayout.addWidget(self.on_list_label, 1, 0, 1, 2)
        self.gridLayout.addWidget(self.on_messages_list_label, 1, 2, 1, 3)
        # self.gridLayout.addWidget(self.no_chat_selected_label, 1, 2, 2, 3)
        # self.no_chat_selected_label.hide()
        self.gridLayout.setRowStretch(1, 2)
        self.gridLayout.setRowStretch(2, 1)
        self.gridLayout.setSpacing(5)

        if self.chats:
            self.on_list_label.hide()
        self.contacts_list.hide()

        self.setCentralWidget(self.centralwidget)

    def create_button_clicked(self):
        if self.buttons_bar.current_button == self.buttons_bar.chats_button:
            NewChatWindow(self).show()
        elif self.buttons_bar.current_button == self.buttons_bar.contacts_button:
            NewContactWindow(self).show()

    def chat_selected(self, item):
        chat_widget = self.chats_list.itemWidget(item)
        self.current_chat = chat_widget.chat
        self.messages.clear()
        self.get_messages_thread.args = [chat_widget.chat.chat_id]
        self.start_getting_messages()

    def contact_selected(self, contact):
        pass

    def start_sending_message(self):
        message = self.message_text_edit.plainText()
        self.add_messages([message])

    def cache_messages(self, messages):
        for m in messages:
            m.chat_id = self.current_chat.chat_id
            if not session.query(Message).filter(Message == m).first():
                session.add(m)
            session.commit()

    def update_contacts_list(self):
        result = session.query(Contact).all()
        self.contacts_list.clear()
        self.contacts = list()
        if result:
            for contact in result:
                self.contacts.append(contact)
                contact_widget = ContactWidget(contact)
                contact_item = QtWidgets.QListWidgetItem()
                contact_item.setSizeHint(QtCore.QSize(100, 70))
                self.contacts_list.addItem(contact_item)
                self.contacts_list.setItemWidget(contact_item, contact_widget)
        else:
            self.on_list_label.show()

    # def update_messages_list(self):
    #     if self.current_chat is not None:
    #         self.get_messages_thread.start()
    #     else:
    #         pass

    def timeout(self):
        self.get_chats_thread.start()
        if self.current_chat is not None:
            self.get_messages_thread.start()

    def complete_getting_chats(self, response):
        if response["status"] == "OK":
            self.chats_list.clear()
            chats = list()
            for chat in response["chats"]:
                image = None
                if chat["username"] in self.contacts:
                    contact = self.contacts[self.contacts.index(chat["username"])]
                    chat["username"] = contact.readable_name
                    image = contact.picture
                chat_obj = Chat(chat["username"], chat["chat_id"], None, None)
                chats.append(chat_obj)
                chat_widget = ChatWidget(chat_obj, api.decrypt_message(chat["last_message"]), image)
                chat_item = QtWidgets.QListWidgetItem()
                chat_item.setSizeHint(QtCore.QSize(100, 70))
                self.chats_list.addItem(chat_item)
                self.chats_list.setItemWidget(chat_item, chat_widget)
            self.loading_movie.stop()
            self.loading_label.hide()
            self.chats = chats
            if self.chats:
                self.on_list_label.hide()

        else:
            QtWidgets.QMessageBox().critical(self, "", response["error"])

    def start_getting_messages(self):
        cached_messages = session.query(Message).filter(Message.chat_id == self.current_chat.chat_id).all()
        if cached_messages:
            self.on_messages_list_label.hide()
        self.add_messages(cached_messages)
        self.get_messages_thread.start()

    def complete_getting_messages(self, response):
        if response["status"] == "OK":
            self.on_messages_list_label.hide()
            cached_messages = set(session.query(Message).filter(Message.chat_id == self.current_chat.chat_id).all())

            all_messages = [Message(m["data"], m["type"].value, m["viewed"],
                                    self.current_chat.chat_id, m["sended_by"], m["name"],
                                    m["unix_time"]) for m in response["messages"]]
            all_messages_set = set(all_messages)

            messages_to_show = cached_messages | all_messages_set
            messages_to_show -= set(self.messages)
            messages_to_show = list(messages_to_show)
            messages_to_show.sort(key=lambda x: x.unix_time)

            self.add_messages(messages_to_show)

            self.cache_messages_thread.args = [messages_to_show]
            self.cache_messages_thread.start()
        else:
            QtWidgets.QMessageBox().critical(self, " ", response["error"])

    def add_messages(self, messages):
        for message in messages:
            sended_by = "You" if message.sended_by == credentials["username"] else message.sended_by
            if message.sended_by in self.contacts:
                sended_by = self.contacts[self.contacts.index(message.sended_by)].readable_name
            msg = TextMessage(text=message.data, username=sended_by)
            if message not in self.messages:
                chat_widget = TextMessageWidget(msg)
                message_item = QtWidgets.QListWidgetItem()
                message_item.setSizeHint(chat_widget.sizeHint())
                self.messages_list.addItem(message_item)
                self.messages_list.setItemWidget(message_item, chat_widget)
                self.messages.append(message)


class NewChatWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setFixedSize(200, 100)
        regular_font.setPointSize(14)
        self.setWindowModality(QtCore.Qt.ApplicationModal)

        self.centralwidget = QtWidgets.QWidget(self)
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.user_id_line = UsernameLineEdit()
        self.add_button = QtWidgets.QPushButton(self)
        self.add_button.setText("Create")
        self.add_button.clicked.connect(self.create_chat)
        self.add_button.setFont(regular_font)
        self.cancel_button = QtWidgets.QPushButton(self)
        self.cancel_button.setText("Cancel")
        self.cancel_button.clicked.connect(self.close)
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

    def finished_creating_chat(self, response):
        if response["status"] == "OK":
            self.close()
        else:
            QtWidgets.QMessageBox().critical(self, " ", response["error"])

    def create_chat(self):
        if len(self.user_id_line.text()) == username_len:
            self.create_chat_thread.function = api.create_chat
            self.create_chat_thread.args = [self.user_id_line.text()]
            self.create_chat_thread.start()
        else:
            QtWidgets.QMessageBox().critical(self, " ", f"Username should be {username_len} characters long")


class NewContactWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.parent = parent

        self.resize(300, 400)
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.centralwidget = QtWidgets.QWidget(self)
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        regular_font.setPointSize(14)

        self.picture_label = RoundImageLabel("img/ghost_user.png", 256)

        self.upload_picture_button = QtWidgets.QPushButton()
        self.upload_picture_button.setText("Upload picture")
        self.upload_picture_button.setFont(regular_font)
        self.upload_picture_button.clicked.connect(self.upload_picture)

        self.username_line = UsernameLineEdit()

        self.name_line = QtWidgets.QLineEdit()
        self.name_line.setPlaceholderText("Name to show")
        self.name_line.setFont(regular_font)

        self.save_button = QtWidgets.QPushButton()
        self.save_button.setText("Save")
        self.save_button.setFont(regular_font)
        self.save_button.clicked.connect(self.save_contact)

        self.picture_path = "img/ghost_user.png"

        self.gridLayout.addWidget(self.picture_label, 0, 0, 1, 1, alignment=QtCore.Qt.AlignCenter)
        self.gridLayout.addWidget(self.upload_picture_button, 1, 0, 1, 1)
        self.gridLayout.addWidget(self.username_line, 2, 0, 1, 1)
        self.gridLayout.addWidget(self.name_line, 3, 0, 1, 1)
        self.gridLayout.addWidget(self.save_button, 4, 0, 1, 1)

        self.setCentralWidget(self.centralwidget)

    def test(self):
        print(1)

    def upload_picture(self):
        fname, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open file', '', "Image files (*.jpg *.png)")
        if fname:
            self.picture_label.update_image(fname, 256, True)
            self.picture_path = fname

    def save_contact(self):
        if self.username_line.text() and self.name_line.text():
            username = self.username_line.text()
            readable_name = self.name_line.text()
            picture = Image.open(self.picture_path)
            if not list(filter(lambda x: x.username == username, self.parent.contacts)):
                if len(username) == username_len:
                    filename = "img/" + username + ".png"
                    picture.save(filename)
                    contact = Contact(username, readable_name, filename)
                    session.add(contact)
                    session.commit()
                    self.parent.contacts.append(Contact(readable_name, username, picture))
                    self.parent.update_contacts_list()
                    self.parent.on_list_label.hide()
                    self.close()
                else:
                    QtWidgets.QMessageBox().critical(self, " ", f"Username should contain of {username_len} characters")
            else:
                QtWidgets.QMessageBox().critical(self, " ", "Contact with this username already exists")
        else:
            QtWidgets.QMessageBox().critical(self, " ", "Fill all the lines")


if __name__ == "__main__":
    try:
        credentials = json.load(open("credentials.json", encoding="utf-8"))
    except FileNotFoundError:
        with open("credentials.json", "w", encoding="utf-8") as f:
            f.write("{}")
    try:
        api = RocketAPI(credentials["login"], credentials["password"])
    except Exception:
        api = RocketAPI("", "")
        print("error")

    db_session.global_init("db/cache.db")
    session = db_session.create_session()

    app = QtWidgets.QApplication([""])
    # chats_window = ChatsWindow()
    # chats_window.show()
    try:
        response = RocketAPI(credentials["login"], credentials["password"]).get_user_data()
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
