from PyQt5 import QtWidgets, QtCore, QtGui
from data.contacts import Contact
from constants import bold_font, regular_font
from rocket import MessageTypes
from constants import username_len
from datetime import datetime
from PIL import Image
import time


class ChatWidget(QtWidgets.QWidget):
    def __init__(self, chat, last_message, contacts, image=None):
        super().__init__()
        self.message = "No messages"
        if last_message["status"] == "OK":
            if last_message["type"] == MessageTypes.Text:
                self.message = last_message["data"]
            else:
                self.message = last_message["data"].name
        self.chat = chat
        if chat.username in contacts:
            contact = contacts[contacts.index(chat.username)]
            chat.username = contact.readable_name
            image = contact.picture
        vbox = QtWidgets.QGridLayout()
        vbox.setAlignment(QtCore.Qt.AlignLeft)
        user_image_label = RoundImageLabel(image, 45, antialiasing=True)
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


class ContactWidget(QtWidgets.QWidget):
    def __init__(self, contact, session):
        super().__init__()

        self.gridLayout = QtWidgets.QGridLayout(self)
        self.contact = contact
        self.session = session

        self.name_label = QtWidgets.QLabel(self)
        self.name_label.setText(contact.readable_name)
        bold_font.setPointSize(16)
        self.name_label.setFont(bold_font)

        print(contact.picture)
        self.contact_image = RoundImageLabel(contact.picture, 45)

        self.username_label = QtWidgets.QLabel()
        self.username_label.setText(contact.username)
        self.username_label.setStyleSheet("color: gray")
        regular_font.setPointSize(12)
        self.username_label.setFont(regular_font)

        self.gridLayout.addWidget(self.contact_image, 0, 0, 2, 1)
        self.gridLayout.addWidget(self.name_label, 0, 1, 1, 1)
        self.gridLayout.addWidget(self.username_label, 1, 1, 1, 1)
        self.gridLayout.setColumnStretch(0, 1)
        self.gridLayout.setColumnStretch(1, 5)
        self.gridLayout.setAlignment(QtCore.Qt.AlignTop)

        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)

        self.setLayout(self.gridLayout)

    def show_menu(self, event):
        contextMenu = QtWidgets.QMenu()
        delete_action = QtWidgets.QAction("Delete")
        delete_action.triggered.connect(self.delete_contact)
        edit_action = QtWidgets.QAction("Edit")
        edit_action.triggered.connect(self.edit_contact)
        contextMenu.addAction(delete_action)
        contextMenu.addAction(edit_action)
        contextMenu.exec(self.mapToGlobal(event))

    def delete_contact(self):
        contact = self.session.query(Contact).filter(Contact.username == self.contact.username).first()
        self.session.delete(contact)
        self.session.commit()
        self.parent().parent().parent().parent().update_contacts_list()

    def edit_contact(self):
        class EditContactWindow(QtWidgets.QMainWindow):
            def __init__(self, contact, parent=None):
                super().__init__(parent=parent)
                self.contact = contact
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

                self.picture_path = contact.picture

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
                if self.name_line.text() and self.username_line.text():
                    contact = self.parent().session.query(Contact).filter(Contact.username == self.contact.username).first()
                    self.parent().session.delete(contact)
                    filename = "img/" + self.contact.username + ".png"
                    Image.open(self.picture_path).save(filename)
                    c = Contact(self.username_line.text(), self.name_line.text(), filename)
                    self.parent().session.add(c)
                    self.parent().session.commit()
                    self.parent().parent().parent().parent().parent().update_contacts_list()
                    self.close()
                else:
                    QtWidgets.QMessageBox.critical(self, " ", "Fill all lines")

        edit_contact_window = EditContactWindow(self.contact, self)
        edit_contact_window.username_line.setText(self.contact.username)
        edit_contact_window.name_line.setText(self.contact.readable_name)
        edit_contact_window.show()


class TextMessageWidget(QtWidgets.QWidget):
    def __init__(self, message):
        super().__init__()
        self.message = message

        self.gridLayout = QtWidgets.QGridLayout(self)

        self.username_label = QtWidgets.QLabel(self.message.sended_by)
        self.username_label.setStyleSheet("color: blue")
        bold_font.setPointSize(14)
        self.username_label.setFont(bold_font)

        self.message_label = QtWidgets.QLabel()
        regular_font.setPointSize(14)
        self.message_label.setFont(regular_font)
        if type(self.message.data) == bytes:
            self.message_label.setText(str(self.message.data, "utf-8"))
        else:
            self.message_label.setText(self.message.data)
        self.message_label.setWordWrap(True)

        self.time_label = QtWidgets.QLabel()
        regular_font.setPointSize(12)
        self.time_label.setFont(regular_font)
        self.time_label.setStyleSheet("color: gray")
        if self.message.unix_time < 2147483647:
            self.time_label.setText(datetime.utcfromtimestamp(self.message.unix_time).strftime('%Y %b %A %H:%M'))
        else:
            self.time_label.setText(datetime.utcfromtimestamp(time.time()).strftime('%Y %b %A %H:%M'))

        self.message_status_label = QtWidgets.QLabel()
        self.message_status_label.setPixmap(QtGui.QPixmap("img/message_sent_local.png").scaled(20, 20, transformMode=QtCore.Qt.SmoothTransformation))

        self.gridLayout.addWidget(self.username_label, 0, 0, 1, 2, alignment=QtCore.Qt.AlignLeft)
        self.gridLayout.addWidget(self.message_label, 1, 0, 1, 2)
        self.gridLayout.addWidget(self.time_label, 1, 2, 1, 1, alignment=QtCore.Qt.AlignRight)
        self.gridLayout.addWidget(self.message_status_label, 0, 2, 1, 1, alignment=QtCore.Qt.AlignRight)
        self.gridLayout.setSpacing(5)
        self.gridLayout.setContentsMargins(11, 5.5, 11, 5.5)
        self.setLayout(self.gridLayout)


class FileMessageWidget(QtWidgets.QWidget):
    def __init__(self, message):
        super().__init__()
        self.message = message

        self.gridLayout = QtWidgets.QGridLayout(self)
        bold_font.setPointSize(14)
        regular_font.setPointSize(12)

        self.filename_label = QtWidgets.QLabel()
        self.filename_label.setFont(bold_font)
        self.filename_label.setText(message.name)

        self.size_label = QtWidgets.QLabel()
        self.size_label.setFont(regular_font)
        self.size_label.setText()

        self.download_file_button = QtWidgets.QPushButton()
        self.download_file_button.setText("Download")

        self.setLayout(self.gridLayout)


class BottomButtonsBar(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent

        self.boxLayout = QtWidgets.QHBoxLayout(self)
        self.button_group = QtWidgets.QButtonGroup(self)

        self.contacts_button = QtWidgets.QPushButton(self)
        self.contacts_button.setText("Contacts")
        self.contacts_button.setMinimumHeight(35)
        self.contacts_button.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)

        self.chats_button = QtWidgets.QPushButton(self)
        self.chats_button.setText("Chats")
        # self.chats_button.setIcon(QtGui.QIcon("img/message_bubble.png"))

        self.chats_button.setMinimumHeight(35)
        self.chats_button.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)

        self.settings_button = QtWidgets.QPushButton(self)
        self.settings_button.setText("Settings")
        self.settings_button.setMinimumHeight(35)
        self.settings_button.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)

        self.button_group.addButton(self.contacts_button)
        self.button_group.addButton(self.chats_button)
        self.button_group.addButton(self.settings_button)
        self.button_group.setExclusive(True)
        self.button_group.buttonPressed.connect(self.button_pressed)
        for button in self.button_group.buttons():
            button.setStyleSheet("border: none")
        self.chats_button.setStyleSheet("color: blue; border: none; border-bottom: 1px solid blue")
        self.current_button = self.chats_button

        self.boxLayout.addWidget(self.contacts_button)
        self.boxLayout.addWidget(self.chats_button)
        self.boxLayout.addWidget(self.settings_button)
        # self.boxLayout.setAlignment(QtCore.Qt.AlignCenter)
        self.boxLayout.setContentsMargins(0, 0, 0, 0)
        # self.groupBox.setStyleSheet("border: 1px solid black;")
        self.setLayout(self.boxLayout)

    def button_pressed(self, btn):
        btn.setStyleSheet("color: blue; border: none; border-bottom: 1px solid blue")
        for button in self.button_group.buttons():
            if button != btn:
                button.setStyleSheet("border: none")
        if btn == self.contacts_button:
            self.parent.chats_list.hide()
            self.parent.contacts_list.show()
            if self.parent.contacts:
                self.parent.on_list_label.hide()
                self.parent.update_contacts_list()
            else:
                self.parent.on_list_label.setText("You have no contacts")
                self.parent.on_list_label.show()
            self.current_button = self.contacts_button
        elif btn == self.chats_button:
            self.parent.contacts_list.hide()
            self.parent.chats_list.show()
            if len(self.parent.chats) == 0:
                self.parent.on_list_label.setText("You have no chats")
                self.parent.on_list_label.show()
            else:
                self.parent.on_list_label.hide()
            self.current_button = self.chats_button


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


class UsernameLineEdit(QtWidgets.QLineEdit):
    def __init__(self):
        super().__init__()

        self.setText("@")
        self.textChanged.connect(self.line_edit_symbol)
        self.setMaxLength(username_len)
        regular_font.setPointSize(14)
        self.setFont(regular_font)

    def line_edit_symbol(self):
        if len(self.text()) < 1:
            self.setText("@")


class RoundImageLabel(QtWidgets.QLabel):
    def __init__(self, picture, size, antialiasing=True):
        super().__init__()

        self.setScaledContents(True)
        picture = picture or "img/ghost_user.png"
        self.update_image(picture, size, antialiasing)

    def update_image(self, picture, size, antialiasing):
        self.Antialiasing = antialiasing
        self.setMaximumSize(size, size)
        self.setMinimumSize(size, size)
        self.radius = size // 2
        self.target = QtGui.QPixmap(self.size())
        self.target.fill(QtCore.Qt.transparent)

        p = QtGui.QPixmap(picture).scaled(
            size, size, QtCore.Qt.KeepAspectRatioByExpanding, QtCore.Qt.SmoothTransformation)

        painter = QtGui.QPainter(self.target)
        if self.Antialiasing:
            painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
            painter.setRenderHint(QtGui.QPainter.HighQualityAntialiasing, True)
            painter.setRenderHint(QtGui.QPainter.SmoothPixmapTransform, True)

        path = QtGui.QPainterPath()
        path.addRoundedRect(
            0, 0, self.width(), self.height(), self.radius, self.radius)

        painter.setClipPath(path)
        painter.drawPixmap(0, 0, p)
        self.setPixmap(self.target)
