from PyQt5 import QtGui
from rocket import RocketAPI
from data.contacts import Contact
import json
from data import db_session
import hashlib

username_len = 9
try:
    credentials = json.load(open("credentials.json", encoding="utf-8"))
except FileNotFoundError:
    with open("credentials.json", "w", encoding="utf-8") as f:
        f.write("{}")
    credentials = json.load(open("credentials.json", encoding="utf-8"))
try:
    db_session.global_init(f"db/{hashlib.sha512(credentials['login'].encode('utf-8')).hexdigest()}.db")
    session = db_session.create_session()
    contacts = session.query(Contact).all()
except Exception as e:
    session = None
    contacts = None
try:
    api = RocketAPI(credentials["login"], credentials["password"])
except Exception as e:
    api = RocketAPI("", "")
try:
    config = json.load(open("config.json", encoding="utf-8"))
except FileNotFoundError:
    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(f, {
            "background_color": "white",
            "text_color": "black",
            "secondary_text_color": "gray",
            "server_address": "https://178.76.236.166:8080",
            "ipfs_api_address": "35.209.84.85:5001/api/v0"
        })
        config = json.load(open("config.json", encoding="utf-8"))
