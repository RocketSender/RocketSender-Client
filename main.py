from PyQt5 import QtWidgets, QtCore, QtGui
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from widgets import (ChatWidget, ContactWidget, TextMessageWidget,
                     BottomButtonsBar, GrowingTextEdit, UsernameLineEdit,
                     RoundImageLabel, SettingsWidget, FileMessageWidget)
from classes import TextMessage
from functions import password_check
from constants import (username_len, api,
                       credentials, config, session, contacts)
from rocket import RocketAPI, RocketAPIThread, MessageTypes
from data import db_session
from data.chats import Chat
from data.contacts import Contact
from data.messages import Message
from threading import Thread
from collections import defaultdict
from PIL import Image
import logging
import platform
import hashlib
import requests
import json
import sqlite3
import time
import copy
import sys
import os


logging.basicConfig(filename="logs.log",
                    format='%(asctime)s %(levelname)s %(name)s %(message)s',
                    level=logging.ERROR)


class SigninWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent=parent)

        self.resize(590, 500)
        self.parent = parent

        self.centralwidget = QtWidgets.QWidget(self)
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)

        logo_box = QtWidgets.QWidget()
        self.logo_label = QtWidgets.QLabel(self.centralwidget)
        self.logo_label.setAlignment(QtCore.Qt.AlignCenter)
        pixmap = QtGui.QPixmap("img/out_logo.png")
        self.logo_label.setPixmap(pixmap.scaled(256, 256,
                                                transformMode=QtCore.Qt.
                                                SmoothTransformation))
        self.name_label = QtWidgets.QLabel("Rocket Sender")
        self.name_label.setStyleSheet("font-weight: medium; font-size: 24px")
        self.name_label.setAlignment(QtCore.Qt.AlignCenter)
        vbox = QtWidgets.QGridLayout()
        vbox.addWidget(self.logo_label, 0, 0, 1, 1)
        vbox.addWidget(self.name_label, 1, 0, 1, 1)
        vbox.setAlignment(QtCore.Qt.AlignTop)
        logo_box.setLayout(vbox)
        self.login_line = QtWidgets.QLineEdit(self.centralwidget)
        self.login_line.setPlaceholderText("Login")
        self.password_line = QtWidgets.QLineEdit(self.centralwidget)
        self.password_line.setPlaceholderText("Password")
        self.password_line.setEchoMode(QtWidgets.QLineEdit.Password)
        self.signin_button = QtWidgets.QPushButton(self.centralwidget)
        self.signin_button.setText("Sign in")
        self.signin_button.clicked.connect(self.signin)
        self.signin_button.setDefault(True)
        self.signup_button = QtWidgets.QPushButton(self.centralwidget)
        self.signup_button.setText("Sign up")
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
        global api, credentials, session, contacts
        login = self.login_line.text()
        password = self.password_line.text()
        if response["status"] == "OK":
            with open("credentials.json", "w", encoding="utf-8") as f:
                response["data"]["login"] = login
                response["data"]["password"] = password
                json.dump(response["data"], f)
            api = RocketAPI(login, password)
            api.credentials = response["data"]
            credentials = json.load(open("credentials.json", "r",
                                         encoding="utf-8"))
            db_session.global_init(f"""db/{hashlib.sha512(credentials['login'].
                                   encode('utf-8')).hexdigest()}.db""")
            session = db_session.create_session()
            contacts = session.query(Contact).all()
            ChatsWindow().show()
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

        logo_box = QtWidgets.QWidget()
        self.logo_label = QtWidgets.QLabel(self.centralwidget)
        self.logo_label.setAlignment(QtCore.Qt.AlignCenter)
        pixmap = QtGui.QPixmap("img/out_logo.png")
        self.logo_label.setPixmap(pixmap.scaled(256, 256,
                                                transformMode=QtCore.Qt.
                                                SmoothTransformation))
        self.name_label = QtWidgets.QLabel("Rocket Sender")
        self.name_label.setStyleSheet("font-weight: medium; font-size: 24px")
        self.name_label.setAlignment(QtCore.Qt.AlignCenter)
        vbox = QtWidgets.QVBoxLayout()
        vbox.addWidget(self.logo_label)
        vbox.addWidget(self.name_label)
        vbox.setAlignment(QtCore.Qt.AlignTop)
        logo_box.setLayout(vbox)
        self.email_line = QtWidgets.QLineEdit(self.centralwidget)
        self.email_line.setPlaceholderText("Email")
        self.login_line = QtWidgets.QLineEdit(self.centralwidget)
        self.login_line.setPlaceholderText("Login")
        self.password_line = QtWidgets.QLineEdit(self.centralwidget)
        self.password_line.setPlaceholderText("Password")
        self.password_line.setEchoMode(QtWidgets.QLineEdit.Password)
        self.second_password_line = QtWidgets.QLineEdit(self.centralwidget)
        self.second_password_line.setPlaceholderText("Enter password again")
        self.second_password_line.setEchoMode(QtWidgets.QLineEdit.Password)
        self.second_password_line.sizePolicy().setHorizontalStretch(1)

        self.signup_button = QtWidgets.QPushButton(self.centralwidget)
        self.signup_button.setText("Sign up")
        self.signup_button.clicked.connect(self.initiate_signup)
        self.error_label = QtWidgets.QLabel()
        self.error_label.setStyleSheet("color: red")

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
        self.timer_label = QtWidgets.QLabel(self.centralwidget)
        self.timer_label.setStyleSheet("color: gray")
        self.timer_label.setText("Token expires in " + str(self.counter) + " sec.")

        self.label = QtWidgets.QLabel("Enter token from email:")
        self.token_line = QtWidgets.QLineEdit(self.centralwidget)
        self.token_line.setMaxLength(7)
        self.token_line.setPlaceholderText("Token")
        self.token_line.setValidator(QtGui.QIntValidator(0, 9999999))
        self.ok_button = QtWidgets.QPushButton(self.centralwidget)
        self.ok_button.setText("Ok")
        self.ok_button.setDefault(True)
        self.ok_button.clicked.connect(self.complete_signup)
        self.cancel_button = QtWidgets.QPushButton(self.centralwidget)
        self.cancel_button.setText("Cancel")
        self.cancel_button.clicked.connect(self.close)
        self.new_token_button = QtWidgets.QPushButton(self.centralwidget)
        self.new_token_button.setText("New token")
        self.new_token_button.setEnabled(False)
        self.new_token_button.clicked.connect(self.new_token)

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
        self.setStyleSheet(f"QLabel {{ color: {config['text_color']} }}")
        self.centralwidget = QtWidgets.QWidget(self)
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.setWindowTitle("Rocket Sender")

        self.current_chat = None

        self.messages_list = QtWidgets.QListWidget(self.centralwidget)
        self.messages_list.setStyleSheet("QListWidget {border: 1px solid lightgrey}")

        self.chats_list = QtWidgets.QListWidget(self.centralwidget)
        self.chats_list.setStyleSheet("QListWidget::item { border-bottom: 1px solid lightgray; } QListWidget {border: 1px solid lightgrey}")
        self.chats_list.itemClicked.connect(self.chat_selected)
        self.chats_list.setMinimumWidth(270)

        self.contacts_list = QtWidgets.QListWidget(self.centralwidget)
        self.contacts_list.setStyleSheet("QListWidget::item { border-bottom: 1px solid lightgray; }; QListWidget {border: 1px solid lightgrey}")
        self.contacts_list.itemClicked.connect(self.contact_selected)
        self.contacts_list.setMinimumWidth(270)

        self.on_list_label = QtWidgets.QLabel("You have no chats")
        self.on_list_label.setStyleSheet("color: gray")
        self.on_list_label.setAlignment(QtCore.Qt.AlignCenter)
        self.on_list_label.setMinimumWidth(270)

        self.on_messages_list_label = QtWidgets.QLabel("You have no messages")
        self.on_messages_list_label.setStyleSheet("color: gray")
        self.on_messages_list_label.setAlignment(QtCore.Qt.AlignCenter)
        self.on_messages_list_label.setText("Select a chat")

        self.obtain_chats = QtCore.QTimer(self)
        self.obtain_chats.timeout.connect(self.timeout)
        self.obtain_chats.start(5000)

        self.loading_label = QtWidgets.QLabel(self.centralwidget)
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

        self.pin_file_button = QtWidgets.QPushButton(self.centralwidget)
        self.pin_file_button.setText("+")
        self.pin_file_button.clicked.connect(self.send_file)

        self.message_text_edit = GrowingTextEdit()
        self.message_text_edit.setPlaceholderText("Message")
        self.message_text_edit.setMinimumHeight(28)
        self.message_text_edit.signal.connect(self.message_text_edit_key_press_event)

        self.send_message_button = QtWidgets.QPushButton(self.centralwidget)
        self.send_message_button.clicked.connect(self.start_sending_message)
        self.send_message_button.setText("Send")

        self.current_chat_label = QtWidgets.QLabel()
        self.current_chat_label.setAlignment(QtCore.Qt.AlignLeft)
        self.current_chat_label.setStyleSheet("font-weight: bold; font-size:15px;")

        self.settings_widget = SettingsWidget()

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

        self.cache_chats_thread = RocketAPIThread()
        self.cache_chats_thread.function = self.cache_chats

        self.send_message_thread = RocketAPIThread()
        self.send_message_thread.function = api.send_message
        self.send_message_thread.signal.connect(self.complete_sending_message)

        self.update_statuses_thread = RocketAPIThread()
        self.update_statuses_thread.function = self.update_statuses

        self.upload_file_thread = RocketAPIThread()
        self.upload_file_thread.function = api.upload_file
        self.upload_file_thread.signal.connect(self.complete_file_upload)

        self.chats = session.query(Chat).order_by(Chat.unix_time.desc()).all()
        self.messages = list()
        self.message_cache = defaultdict()
        for message in session.query(Message).order_by(Message.unix_time).all():
            if message.chat_id in self.message_cache:
                self.message_cache[message.chat_id].append(message)
            else:
                self.message_cache[message.chat_id] = [message]

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
        self.gridLayout.addWidget(self.settings_widget, 1, 0, 1, 2)
        self.gridLayout.addWidget(self.current_chat_label, 0, 2, 1, 3)

        self.gridLayout.setRowStretch(1, 2)
        self.gridLayout.setRowStretch(2, 1)
        self.gridLayout.setSpacing(5)

        if self.chats:
            self.on_list_label.hide()
        self.contacts_list.hide()
        self.settings_widget.hide()
        self.start_getting_chats()

        self.setCentralWidget(self.centralwidget)

    def message_text_edit_key_press_event(self, e):
        if e.key() == QtCore.Qt.Key_Return:
            self.start_sending_message()

    def create_button_clicked(self):
        if self.buttons_bar.current_button == self.buttons_bar.chats_button:
            NewChatWindow(self).show()
        elif self.buttons_bar.current_button == self.buttons_bar.contacts_button:
            NewContactWindow(self).show()

    def start_getting_chats(self):
        cached_chats = session.query(Chat).order_by(Chat.unix_time.desc()).all()
        for chat in cached_chats:
            chat_obj = Chat(chat.username, chat.chat_id, chat.last_message, None)
            image = None
            self.chats.append(chat_obj)
            # payload = {"status": "OK", "data": chat.last_message, "type": MessageTypes.Text, "sent_by": "@8025a412", "viewed": True}
            chat_obj.last_message = json.loads(chat.last_message)
            chat_widget = ChatWidget(chat_obj, image, credentials["username"])
            chat_item = QtWidgets.QListWidgetItem()
            chat_item.setSizeHint(QtCore.QSize(100, 70))
            self.chats_list.addItem(chat_item)
            self.chats_list.setItemWidget(chat_item, chat_widget)
        self.get_chats_thread.start()

    def complete_getting_chats(self, response):
        if response["status"] == "OK":
            self.chats_list.clear()
            chats = list()
            for chat in response["chats"]:
                image = None
                data = None
                unix_time = 0
                decrypted_message = None
                if chat["last_message"] is not None:
                    if int(chat["last_message"]["type"]) == MessageTypes.Text:
                        decrypted_message = api.decrypt_message(chat["last_message"])
                        if decrypted_message["status"] == "error":
                            data = "No messages"
                            unix_time = 0
                        else:
                            data = decrypted_message["data"]
                            unix_time = decrypted_message["unix_time"]
                    elif int(chat["last_message"]["type"]) == MessageTypes.Document:
                        data = "Document"
                        decrypted_message = {"data": data, "status": "OK", "type": MessageTypes.Document}

                chat_obj = Chat(chat["username"], chat["chat_id"], decrypted_message, unix_time)
                chats.append(chat_obj)
                chat_widget = ChatWidget(chat_obj, image, credentials["username"])
                chat_item = QtWidgets.QListWidgetItem()
                chat_item.setSizeHint(QtCore.QSize(100, 70))
                self.chats_list.addItem(chat_item)
                self.chats_list.setItemWidget(chat_item, chat_widget)
            self.cache_chats_thread.args = [chats]
            self.cache_chats_thread.start()
            self.loading_movie.stop()
            self.loading_label.hide()
            self.chats = chats
            if self.chats:
                self.on_list_label.hide()

        elif response["error"] == "No internet connection":
            return
        else:
            pass

    def cache_chats(self, chats):
        session = db_session.create_session()
        for chat in chats:
            cached_chat = session.query(Chat).filter(Chat == chat).first()
            if not cached_chat:
                chat.last_message = json.dumps(chat.last_message)
                session.add(chat)
            elif cached_chat.unix_time != chat.unix_time:
                cached_chat.unix_time = chat.unix_time
                cached_chat.last_message = json.dumps(chat.last_message)
                session.merge(cached_chat)
        session.commit()

    def chat_selected(self, item):
        chat_widget = self.chats_list.itemWidget(item)
        chat = chat_widget.chat
        self.current_chat = chat
        self.messages.clear()
        self.messages_list.clear()
        username = list(filter(lambda x: x.username == chat.username, contacts))
        if not username:
            username = chat.username
        else:
            username = username[0].readable_name
        self.current_chat_label.setText(username)
        self.get_messages_thread.args = [chat.chat_id]
        self.start_getting_messages()

    def contact_selected(self, item):
        pass

    def send_file(self):
        fname, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Choose file', '', "All files (*)")
        if fname:
            self.upload_file_thread.args = [fname, self.current_chat.username, self.current_chat.chat_id]
            self.upload_file_thread.start()

    def complete_file_upload(self, response):
        if response["status"] == "OK":
            del response["status"]
            data = json.dumps(response).encode("utf-8")
            row = len(self.messages_list)
            message = Message(data=data, type=MessageTypes.Document, viewed=False,
                              chat_id=self.current_chat.chat_id, sent_by=credentials["username"],
                              row=row)
            self.send_message_thread.args = [MessageTypes.Document,
                                             data,
                                             self.current_chat.chat_id,
                                             self.current_chat.username,
                                             row, message]
            self.send_message_thread.start()
            self.cache_messages([message])
            self.add_messages([message])
        else:
            QtWidgets.QMessageBox().critical(self, " ", response["error"])

    def start_sending_message(self):
        try:
            text = self.message_text_edit.toPlainText()
            self.message_text_edit.setPlainText("")
            self.message_text_edit.repaint()
            self.messages_list.scrollToBottom()
            row = len(self.messages_list)
            message = Message(data=text, type=MessageTypes.Text, viewed=False,
                              chat_id=self.current_chat.chat_id,
                              sent_by=credentials["username"], row=row)
            self.send_message_thread.args = [MessageTypes.Text,
                                             bytes(text, "utf-8"),
                                             message.chat_id, self.current_chat.username, row,
                                             message]
            self.send_message_thread.start()
            self.cache_messages([message])
            self.add_messages([message])
        except Exception as e:
            logging.error(e)

    def complete_sending_message(self, response):
        row = response[1]
        if response[0]["status"] == "OK":
            self.messages_list.itemWidget(self.messages_list.item(row)).message_status_label.setPixmap(QtGui.QPixmap("img/message_sent_server.png").scaled(20, 20, transformMode=QtCore.Qt.SmoothTransformation))
            message = response[2]
            message.unix_time = response[0]["send_time"]
            session.merge(message)
            session.commit()
        else:
            logging.error("error sending the message: " + response[0]["error"])

    def cache_messages(self, messages):
        session = db_session.create_session()
        for m in messages:
            m.chat_id = self.current_chat.chat_id
            cached_message = session.query(Message).filter(Message.unix_time == m.unix_time and Message.chat_id == m.chat_id).first()
            if not cached_message:
                session.add(m)
            session.commit()

    def update_statuses(self, messages):
        try:
            session = db_session.create_session()
            for n, message in enumerate(messages):
                cached_message = session.query(Message).filter(Message.unix_time == message.unix_time and
                                                               Message.chat_id == message.chat_id).first()
                if cached_message is not None:
                    if cached_message.viewed != message.viewed:
                        self.messages_list.itemWidget(self.messages_list.item(n)).message_status_label.setPixmap(QtGui.QPixmap("img/message_delivered.png").scaled(20, 20, transformMode=QtCore.Qt.SmoothTransformation))
                        cached_message.viewed = message.viewed
                        if cached_message.type == MessageTypes.Document:
                            cached_message.data = message.data
                        session.commit()
        except Exception as e:
            logging.warning(e)

    def update_contacts_list(self):
        result = session.query(Contact).all()
        self.contacts_list.clear()
        contacts = list()
        if result:
            for contact in result:
                contacts.append(contact)
                contact_widget = ContactWidget(contact, session)
                contact_item = QtWidgets.QListWidgetItem()
                contact_item.setSizeHint(QtCore.QSize(100, 70))
                self.contacts_list.addItem(contact_item)
                self.contacts_list.setItemWidget(contact_item, contact_widget)
        else:
            self.on_list_label.show()

    def timeout(self):
        self.get_chats_thread.start()
        if self.current_chat is not None:
            self.get_messages_thread.start()

    def start_getting_messages(self):
        cached_messages = session.query(Message).filter(Message.chat_id == self.current_chat.chat_id).all()
        if cached_messages:
            self.on_messages_list_label.hide()
            self.add_messages(cached_messages, True)
        self.get_messages_thread.start()

    def complete_getting_messages(self, response):
        if response["status"] == "OK":
            if response["messages"]:
                self.on_messages_list_label.hide()
                try:
                    cached_messages = set(self.message_cache[self.current_chat.chat_id])
                except:
                    cached_messages = set()
                all_messages = []
                for m in response["messages"]:
                    msg = Message(data=m["data"], type=m["type"].value,
                                  viewed=m["viewed"], chat_id=self.current_chat.chat_id,
                                  sent_by=m["sent_by"], unix_time=m["unix_time"],
                                  key=m["key"], signature=m["signature"])
                    all_messages.append(msg)

                all_messages_set = set(all_messages)
                messages_to_show = all_messages_set - cached_messages
                if messages_to_show:
                    messages_to_show = list(messages_to_show)
                    if platform.system() == "Darwin":
                        for msg in messages_to_show:
                            if msg.sent_by != credentials["username"]:
                                os.system(f'''osascript -e \'display
                                              notification "{msg.data}" with
                                              title "{msg.sent_by}" sound
                                              name "Chord"\'''')
                    messages_to_show.sort(key=lambda x: x.unix_time)

                    self.add_messages(messages_to_show)
                    self.cache_messages(messages_to_show)

                    if self.current_chat.chat_id in self.message_cache:
                        self.message_cache[self.current_chat.chat_id] += messages_to_show
                    else:
                        self.message_cache[self.current_chat.chat_id] = messages_to_show
                    self.messages_list.scrollToBottom()
                self.update_statuses_thread.args = [all_messages]
                self.update_statuses_thread.start()

        else:
            print(response["error"])

    def add_messages(self, messages, scroll=False):
        for message in messages:
            sent_by = "You" if message.sent_by == credentials["username"] else message.sent_by
            if message.sent_by in contacts:
                sent_by = contacts[contacts.index(message.sent_by)].readable_name
            if message not in self.messages:
                message_for_widget = copy.copy(message)
                if message_for_widget.type == MessageTypes.Text:
                    chat_widget = TextMessageWidget(message_for_widget)
                elif message_for_widget.type == MessageTypes.Document:
                    chat_widget = FileMessageWidget(message_for_widget)
                if message.viewed:
                    chat_widget.message_status_label.setPixmap(QtGui.QPixmap("img/message_delivered.png").scaled(20, 20, transformMode=QtCore.Qt.SmoothTransformation))
                elif not message.viewed and message.unix_time < 2147483647:
                    chat_widget.message_status_label.setPixmap(QtGui.QPixmap("img/message_sent_server.png").scaled(20, 20, transformMode=QtCore.Qt.SmoothTransformation))
                else:
                    chat_widget.message_status_label.setPixmap(QtGui.QPixmap("img/message_sent_local.png").scaled(20, 20, transformMode=QtCore.Qt.SmoothTransformation))
                message_item = QtWidgets.QListWidgetItem()
                message_item.setSizeHint(chat_widget.sizeHint())
                message_item.setFlags(QtCore.Qt.ItemIsSelectable)
                self.messages_list.addItem(message_item)
                self.messages_list.setItemWidget(message_item, chat_widget)
                self.messages.append(message)
        if scroll:
            self.messages_list.scrollToBottom()

    def add_chats(self, chats):
        for chat in chats:
            chat.last_message = api.decrypt_message(chat.last_message)
            chat_widget = ChatWidget(chat, None, credentials["username"])
            chat_item = QtWidgets.QListWidgetItem()
            chat_item.setSizeHint(QtCore.QSize(100, 70))
            self.chats_list.addItem(chat_item)
            self.chats_list.setItemWidget(chat_item, chat_widget)


class NewChatWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setFixedSize(250, 100)
        self.setWindowModality(QtCore.Qt.ApplicationModal)

        self.centralwidget = QtWidgets.QWidget(self)
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.user_id_line = UsernameLineEdit()
        self.add_button = QtWidgets.QPushButton(self)
        self.add_button.setText("Create")
        self.add_button.setDefault(True)
        self.add_button.clicked.connect(self.create_chat)
        self.cancel_button = QtWidgets.QPushButton(self)
        self.cancel_button.setText("Cancel")
        self.cancel_button.clicked.connect(self.close)
        self.label = QtWidgets.QLabel("Username:")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 3)
        self.gridLayout.addWidget(self.user_id_line, 0, 2, 1, 2)
        self.gridLayout.addWidget(self.add_button, 1, 3, 1, 1)
        self.gridLayout.addWidget(self.cancel_button, 1, 2, 1, 1)

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

        self.picture_label = RoundImageLabel("img/ghost_user.png", 256)

        self.upload_picture_button = QtWidgets.QPushButton()
        self.upload_picture_button.setText("Choose picture")
        self.upload_picture_button.clicked.connect(self.upload_picture)

        self.username_line = UsernameLineEdit()

        self.name_line = QtWidgets.QLineEdit()
        self.name_line.setPlaceholderText("Name to show")

        self.save_button = QtWidgets.QPushButton()
        self.save_button.setText("Save")
        self.save_button.clicked.connect(self.save_contact)

        self.picture_path = "img/ghost_user.png"

        self.gridLayout.addWidget(self.picture_label, 0, 0, 1, 1, alignment=QtCore.Qt.AlignCenter)
        self.gridLayout.addWidget(self.upload_picture_button, 1, 0, 1, 1)
        self.gridLayout.addWidget(self.username_line, 2, 0, 1, 1)
        self.gridLayout.addWidget(self.name_line, 3, 0, 1, 1)
        self.gridLayout.addWidget(self.save_button, 4, 0, 1, 1)

        self.setCentralWidget(self.centralwidget)

    def upload_picture(self):
        fname, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open file', '', "Image files (*.jpg *.png)")
        if fname:
            self.picture_label.update_image(fname, 256, True)
            self.picture_path = fname

    def save_contact(self):
        global contacts
        if self.username_line.text() and self.name_line.text():
            username = self.username_line.text()
            readable_name = self.name_line.text()
            picture = Image.open(self.picture_path)
            if not list(filter(lambda x: x.username == username, contacts)):
                if len(username) == username_len:
                    filename = "img/" + username + ".png"
                    picture.save(filename)
                    contact = Contact(username, readable_name, filename)
                    session.add(contact)
                    session.commit()
                    contacts.append(Contact(readable_name, username, picture))
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
    app = QtWidgets.QApplication(sys.argv)
    try:
        response = RocketAPI(credentials["login"], credentials["password"]).get_user_data()
        if response["status"] == "OK" or response["error"] == "No internet connection":
            chats_window = ChatsWindow()
            chats_window.show()
        else:
            print(response["error"])
            main = SigninWindow()
            main.show()
    except Exception as e:
        logging.warning(e)
        main = SigninWindow()
        main.show()
    app.setApplicationName("Rocket Sender")
    app.setWindowIcon(QtGui.QIcon("img/logo.png"))
    app.exec()
