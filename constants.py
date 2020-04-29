from PyQt5 import QtGui
from rocket import RocketAPI
import json

regular_font = QtGui.QFont("fonts/Roboto-Regular.ttf")
bold_font = QtGui.QFont("fonts/Roboto-Black.ttf")
username_len = 9
try:
    credentials = json.load(open("credentials.json", encoding="utf-8"))
except FileNotFoundError:
    with open("credentials.json", "w", encoding="utf-8") as f:
        f.write("{}")
    credentials = json.load(open("credentials.json", encoding="utf-8"))
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
            "server_address": "https://178.76.236.166:8080"
        })
        config = json.load(open("config.json", encoding="utf-8"))
