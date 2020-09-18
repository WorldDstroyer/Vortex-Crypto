import os
import sys
import random
import string
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

class Interface(QMainWindow):
    def __init__(self):
        super(Interface, self).__init__()
        self.setWindowTitle("Vortex (VTX) Crypto-R VID: 1.0.0")
        self.setGeometry(50, 50, 400, 600)
        self.initUI()

    def initUI(self):
        self.InputLabel = QtWidgets.QLabel(self)
        self.InputLabel.setText("Input Data:")
        self.InputLabel.setFont(QFont("Arial bold", 12))
        self.InputLabel.move(140, 10)

    def Update(self):
        print("!")

def ParentWindow():
    Application = QApplication(sys.argv)
    Window = Interface()
    Window.show()
    sys.exit(Application.exec_())

ParentWindow()
