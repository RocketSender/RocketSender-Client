from PyQt5 import QtCore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
import hashlib
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import enum
import os
from functions import get_tor_session, handle_request
from data import db_session


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# LINK = "http://35.209.84.85:8080"


class MessageTypes(enum.IntEnum):
    Text = 1
    Photo = 2
    Document = 3
    Sticker = 4
    VoiceMessage = 5


class RocketAPIThread(QtCore.QThread):
    signal = QtCore.pyqtSignal('PyQt_PyObject')

    def __init__(self):
        QtCore.QThread.__init__(self)
        self.function = None
        self.args = []

    def run(self):
        response = self.function(*self.args)
        self.signal.emit(response)


class RocketAPI:
    def __init__(self, login, password):
        self.login = login
        self.password = password
        self.credentials = json.load(open("credentials.json", encoding="utf-8"))
        self.session = requests.Session()

    def initiate_signup(self, email: str):
        payload = {
            "email": email
        }
        return handle_request("initiate_registration", payload, self.session.post)

    def complete_signup(self, email: str, password: str, public_key: str, token: str, login: str) -> dict:
        payload = {
            "email": email,
            "password": password,
            "public_key": public_key,
            "token": token,
            "login": login
        }
        return handle_request("complete_registration", payload, self.session.post)

    def sign_in(self, login: str, password: str):
        payload = {
            "login": login,
            "password": password
        }
        return handle_request("get_user_data", payload, self.session.get)

    def get_user_data(self) -> dict:
        payload = {
            "login": self.login,
            "password": self.password
        }
        return handle_request("get_user_data", payload, self.session.get)

    def get_user_chats(self):
        payload = {
            "login": self.login,
            "password": self.password
        }
        response = handle_request("get_user_chats", payload, self.session.get)
        return response

    def get_all_messages(self, chat_id):
        payload = {
            "login": self.login,
            "password": self.password,
            "chat_id": chat_id
        }
        return handle_request("get_all_messages", payload, self.session.get)

    def get_last_message(self, chat_id):
        payload = {
            "login": self.login,
            "password": self.password,
            "chat_id": chat_id
        }
        return handle_request("get_last_message", payload, self.session.get)

    def get_public_key(self, username):
        payload = {
            "login": self.login,
            "password": self.password,
            "username": username
        }
        return handle_request("get_public_key", payload, self.session.get)

    def create_chat(self, username):
        payload = {
            "login": self.login,
            "password": self.password,
            "user": username
        }
        return handle_request("create_chat", payload, self.session.post)

    def send_message(self, type_: int, data: bytes, chat_id: str, username: str, row=None, msg=None):
        encrypted_data = self.encrypt_data(data, username)
        if encrypted_data["status"] == "OK":
            payload = {
                "login": self.login,
                "password": self.password,
                "data": encrypted_data["data"],
                "signature": encrypted_data["signature"],
                "keys": encrypted_data["keys"],
                "chat_id": chat_id,
                "name": None,
                "type": type_.value
            }
            return handle_request("send_message", payload, self.session.post), row, msg

        else:
            return {"status": "error", "error": encrypted_data["error"]}, row, msg

    def get_all_messages(self, chat_id):
        payload = {
            "login": self.login,
            "password": self.password,
            "chat_id": chat_id
        }
        response = handle_request("get_all_messages", payload, self.session.get)
        if response["status"] == "OK":
            response["messages"] = [self.decrypt_message(message) for message in response["messages"]]
            return response
        else:
            return response

    def decrypt_message(self, message):
        from constants import session, config
        from data.users import User
        if session is None:
            session = db_session.create_session()
        unpadder = padding.PKCS7(128).unpadder()
        my_private = serialization.load_pem_private_key(open(hashlib.sha512(bytes(self.credentials["login"], "utf-8")).hexdigest() + ".pem", "rb").read(), password=bytes(self.credentials["password"], "utf-8"), backend=default_backend())
        if message["sent_by"] == self.credentials["username"]:
            public_key = my_private.public_key()
        else:
            cached_user = session.query(User).filter(User.username == message["sent_by"]).first()
            if cached_user:
                pub_response = {"status": "OK", "public_key": cached_user.public_key}
            else:
                pub_response = self.get_public_key(message["sent_by"])
                user = User()
                user.username = message["sent_by"]
                user.public_key = pub_response["public_key"]
                session.add(user)
                session.commit()
            if pub_response["status"] == "OK":
                public_key = serialization.load_pem_public_key(bytes(pub_response["public_key"], "utf-8"), backend=default_backend())
            else:
                return {"status": "error", "error": "Error getting users public key"}
        key_iv = my_private.decrypt(
            bytes.fromhex(message["key"]),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )
        key = key_iv[:32]
        iv = key_iv[32:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(bytes.fromhex(message["data"])) + decryptor.finalize()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

        if message["type"] == MessageTypes.Text:
            public_key.verify(
                bytes.fromhex(message["signature"]),
                hashlib.sha512(decrypted_data).digest(),
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA512()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )
        payload = {
            "status": "OK",
            "data": decrypted_data.decode("utf-8"),
            "sent_by": message["sent_by"],
            "type": MessageTypes(int(message["type"])),
            "unix_time": message["unix_time"],
            "viewed": message["viewed"],
            "status": "OK",
            "key": key_iv.hex(),
            "signature": message["signature"]
        }

        return payload

    def upload_file(self, filename, username, chat_id):
        from constants import config
        with open(filename, "rb") as f:
            response = self.encrypt_data(f.read(), username)
            if response["status"] == "OK":
                r = self.session.post(config["server_address"] + "/api/upload_file", headers={"login": self.login, "password": self.password, "chat_id": chat_id}, files={os.path.basename(filename): response["data"]}, verify=False)
                if r.status_code == 200:
                    return {"status": "OK", "name": r.json()["file_name"],
                            "file_id": r.json()["file_id"], "size": r.json()["file_size"],
                            "signature": response["signature"], "keys": response["keys"]}
            return {"status": "error", "error": response["error"]}

    def download_file(self, file_data, sent_by):
        from constants import config
        import sys
        r = self.session.get(config["server_address"] + "/api/get_file", json={"login": self.login, "password": self.password, "file_id": file_data["file_id"]}, verify=False)
        return self.decrypt_data(r.text,
                                 file_data["keys"][self.credentials["username"]],
                                 file_data["signature"], sent_by)

    def encrypt_data(self, data, username):
        from constants import session, config
        from data.users import User
        cached_user = session.query(User).filter(User.username == username).first()
        if cached_user:
            response = {"status": "OK", "public_key": cached_user.public_key}
        else:
            response = self.get_public_key(username)
            if response["status"] == "OK":
                user = User()
                user.username = username
                user.public_key = response["public_key"]
                session.add(user)
                session.commit()
            else:
                print(response["error"])
                return {"status": "error", "error": response["error"]}
        if response["status"] == "OK":
            # Pad data
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()

            # Define backend and key + iv
            backend = default_backend()
            key = os.urandom(32)
            iv = os.urandom(16)
            key_iv = key + iv

            # Encrypt all data
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Get public key of user
            users_pub = serialization.load_pem_public_key(bytes(response["public_key"], "utf-8"), backend=default_backend())

            # Get your private and public keys
            my_private = serialization.load_pem_private_key(open(hashlib.sha512(bytes(self.credentials["login"], "utf-8")).hexdigest() + ".pem", "rb").read(), password=bytes(self.credentials["password"], "utf-8"), backend=default_backend())
            my_pub = my_private.public_key()

            # Encrypt keys
            user_encrypted_key = users_pub.encrypt(
                key_iv,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
            my_encrypted_key = my_pub.encrypt(
                key_iv,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )

            # Sign hash of data
            signature = my_private.sign(
                hashlib.sha512(data).digest(),
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA512()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )

            users_keys = {username: user_encrypted_key.hex(), self.credentials["username"]: my_encrypted_key.hex()}

            payload = {
                "status": "OK",
                "data": encrypted_data.hex(),
                "signature": signature.hex(),
                "keys": users_keys
            }
            return payload
        else:
            return {"status": "error", "error": response["error"]}

    def decrypt_data(self, data, key, signature, username):
        from constants import credentials, session, config
        from data.users import User
        unpadder = padding.PKCS7(128).unpadder()
        my_private = serialization.load_pem_private_key(open(hashlib.sha512(bytes(self.credentials["login"], "utf-8")).hexdigest() + ".pem", "rb").read(), password=bytes(self.credentials["password"], "utf-8"), backend=default_backend())
        if username == self.credentials["username"]:
            public_key = my_private.public_key()
        else:
            cached_user = session.query(User).filter(User.username == username).first()
            if cached_user:
                pub_response = {"status": "OK", "public_key": cached_user.public_key}
            else:
                pub_response = self.get_public_key(username)
                user = User()
                user.username = username
                user.public_key = pub_response["public_key"]
                session.add(user)
                session.commit()
            if pub_response["status"] == "OK":
                public_key = serialization.load_pem_public_key(bytes(pub_response["public_key"], "utf-8"), backend=default_backend())
            else:
                return {"status": "error", "error": "Error getting users public key"}
        key_iv = my_private.decrypt(
            bytes.fromhex(key),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )
        key = key_iv[:32]
        iv = key_iv[32:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(bytes.fromhex(data)) + decryptor.finalize()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

        public_key.verify(
            bytes.fromhex(signature),
            hashlib.sha512(decrypted_data).digest(),
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA512()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        payload = {
            "status": "OK",
            "data": decrypted_data,
            "sent_by": username,
            "key": key_iv.hex(),
            "signature": signature
        }

        return payload

    def get_ip(self):
        return self.session.get("https://httpbin.org/ip").text
