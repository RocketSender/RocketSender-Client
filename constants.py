from PyQt5 import QtGui
from rocket import RocketAPI
import json

regular_font = QtGui.QFont("fonts/Roboto-Regular.ttf")
bold_font = QtGui.QFont("fonts/Roboto-Black.ttf")
username_len = 9
LINK = "https://178.76.236.166:8080"
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
    print("error")
