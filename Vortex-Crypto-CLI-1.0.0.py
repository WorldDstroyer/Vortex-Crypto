import os
import sys
import subprocess
import time
import colorama
import random
import secrets
import string
import base64

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import MD2, MD4, MD5, SHA1, SHA256, SHA512, SHA3_256, SHA3_512
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

# - Terminal Color Definitions
RESET = '\033[0m'
# - Formatting Codes (Windows Incompatible)
BOLD = '\033[1m'
DIM = '\033[2m'
UNDERLINE = '\033[4m'
BLINK = '\033[5m'
INVERTED = '\033[7m'
HIDDEN = '\033[8m'
#-------------------------#
# - Background Colors
BDEFAULT = '\033[49m'
BWHITE = '\033[107m'
BLIGHTCYAN = '\033[106m'
BLIGHTMAGENTA = '\033[105m'
BLIGHTBLUE = '\033[104m'
BLIGHTYELLOW = '\033[103m'
BLIGHTGREEN = '\033[102m'
BLIGHTRED = '\033[101m'
BDARKGREY = '\033[100m'
BLIGHTGREY = '\033[47m'
BCYAN = '\033[46m'
BMAGENTA = '\033[45'
BBLUE = '\033[44m'
BYELLOW = '\033[43m'
BGREEN = '\033[42m'
BBLACK = '\033[40m'
BRED = '\033[41m'
#-------------------------#
# - Text Colors
CLEAR_SCREEN = '\033[2J'
WHITE = '\033[97m'
LIGHTCYAN = '\033[96m'
LIGHTMAGENTA = '\033[95m'
LIGHTBLUE = '\033[94m'
LIGHTYELLOW = '\033[93m'
LIGHTGREEN = '\033[92m'
LIGHTRED = '\033[91m'
DARKGREY = '\033[90m'
LIGHTGREY = '\033[37m'
CYAN = '\033[36m'
MAGENTA = '\033[35m'
BLUE = '\033[34m'
YELLOW = '\033[33m'
GREEN = '\033[32m'
BLACK = '\033[30m'
DEFAULT = '\033[39m'
RED = '\033[31m'

colorama.init()

THEMECOLOR = LIGHTCYAN

def F_Theme_Read():
    global THEMECOLOR
    global WHITE
    global LIGHTCYAN
    global LIGHTMAGENTA
    global LIGHTBLUE
    global LIGHTYELLOW
    global LIGHTGREEN
    global LIGHTRED
    global DARKGREY
    global LIGHTGREY
    global CYAN
    global MAGENTA
    global BLUE
    global YELLOW
    global GREEN
    global BLACK
    global DEFAULT
    global RED
    try:
        with open("Theme.ini", "r") as ThemeFile:
            Theme = ThemeFile.readline().rstrip()
            if Theme == "WHITE": THEMECOLOR = WHITE
            elif Theme == "LIGHTCYAN": THEMECOLOR = LIGHTCYAN
            elif Theme == "LIGHTMAGENTA": THEMECOLOR = LIGHTMAGENTA
            elif Theme == "LIGHTBLUE": THEMECOLOR = LIGHTBLUE
            elif Theme == "LIGHTYELLOW": THEMECOLOR = LIGHTYELLOW
            elif Theme == "LIGHTGREEN": THEMECOLOR = LIGHTGREEN
            elif Theme == "LIGHTRED": THEMECOLOR = LIGHTRED
            elif Theme == "DARKGREY": THEMECOLOR = DARKGREY
            elif Theme == "LIGHTGREY": THEMECOLOR = LIGHTGREY
            elif Theme == "CYAN": THEMECOLOR = CYAN
            elif Theme == "MAGENTA": THEMECOLOR = MAGENTA
            elif Theme == "BLUE": THEMECOLOR = BLUE
            elif Theme == "YELLOW": THEMECOLOR = YELLOW
            elif Theme == "GREEN": THEMECOLOR = GREEN
            elif Theme == "BLACK": THEMECOLOR = BLACK
            elif Theme == "DEFAULT": THEMECOLOR = DEFAULT
            elif Theme == "RED": THEMECOLOR = RED

            ThemeFile.close()
    except FileNotFoundError:
        print(LIGHTRED + "Error: Initial theme configuration file 'Theme.ini' not found." + THEMECOLOR)
        time.sleep(1.0)
        F_Main()

F_Theme_Read()

Program_Directory = os.path.dirname(__file__)

Program_Header = THEMECOLOR + '''
----------------------------------------------------------------------------------------------
| __     __         _                  ____                  _                               |
| \ \   / /__  _ __| |_ _____  __     / ___|_ __ _   _ _ __ | |_ ___                         |
|  \ \ / / _ \| '__| __/ _ \ \/ /____| |   | '__| | | | '_ \| __/ _ \                        |
|   \ V / (_) | |  | ||  __/>  <_____| |___| |  | |_| | |_) | || (_) |                       |
|    \_/ \___/|_|   \__\___/_/\_\     \____|_|   \__, | .__/ \__\___/                        |
|                                                |___/|_|                                    |
|                                                                                            |
| Module: Vortex-Crypto-CLI                                                                  |
| Version: 1.0.0, (Base: 1.2.0)                                                              |
| Author: WorldDstroyer                                                                      |
| Date: 11-17-2020                                                                           |
| Description: A lightweight CLI version of Vortex-Crypto, without any GUI libraries.        |
|                                                                                            |
| Manual Guide:                                                                              |
| For program help, you may refer to the "help" options for each Vortex-Crypto module.       |
| The "theme" setting is a color value loaded from (Theme.ini), and it does not affect text  |
| that uses special color attributes.                                                        |
----------------------------------------------------------------------------------------------'''

AES_Help = THEMECOLOR + '''
----------------------------------------------------------------------------------------------
| - Symmetric Encryption:                                                                    |
|                                                                                            |
| 1. Enter your plaintext input data.                                                        |
|                                                                                            |
| 2. Enter your encryption/decryption key (AES is a symmetric encryption algorithm,          |
| so the same key is used for both the encryption and decryption of data).                   |
|                                                                                            |
| 3. The 'Password' input length no longer matters, as a secure key is derived from the      |
| input password during the encryption process.                                              |
|                                                                                            |
| 4. Click on 'Encrypt,' and your data will be encrypted using the given key, and a          |
| randomly generated initialization vector (IV). You will need to decrypt your data using    |
| the IV generated upon encryption, as this is the 'seed' that randomizes the ciphertext     |
| digest.                                                                                    |
|                                                                                            |
| 5. Your ciphertext (encrypted data) will be output accordingly. To decrypt your data,      |
| just input the ciphertext in the 'Input' field, along with the key and your cipher's       |
| unique IV, and click 'Decrypt.'                                                            |
----------------------------------------------------------------------------------------------'''

RSA_Help = THEMECOLOR + '''
----------------------------------------------------------------------------------------------
| - Asymmetric Encryption:                                                                   |
|                                                                                            |
| 1. Generate your public and private key pair with the given length (either 1024, 2048,     |
| or 4096).                                                                                  |
|                                                                                            |
| 2. Use your public and private keys to sign, encrypt, or decrypt data.                     |
----------------------------------------------------------------------------------------------'''

print(Program_Header)

# - Labeling and Formatting Reference Guide
# VOD = "Vortex Option Dictionary" - Used exclusively for option lists.

# - Progress function written by GitHub user vladignatyev.
def Progress_Bar(count, total, status=""):
    Bar_Length = 25
    Filled_Length = int(round(Bar_Length * count / float(total)))

    Percentage = round(100.0 * count / float(total), 1)
    Bar = "#" * Filled_Length + "-" * (Bar_Length - Filled_Length)

    sys.stdout.write("[%s] %s%s %s\r" % (Bar, Percentage, "%", status))
    sys.stdout.flush()

def Shell_Reset():
    subprocess.call('cls',shell=True)
    global Program_Header
    print(Program_Header)
    F_Main()

def F_Main():
    F_Theme_Read()
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/Main                   |
------------------------------------------'''
    print(Function_Header)
    VOD = \
'''\
%s1: Configure (Theme.ini)%s
2: Symmetric Encryption
3: Asymmetric Encryption
4: Encoding
5: Hash
6: Random
7: Storage
!: Exit\
''' % (LIGHTGREEN, THEMECOLOR)
    print(VOD + LIGHTYELLOW)
    Option = input("")

    if Option == "1" or Option == "theme": F_Theme_Configure()
    elif Option == "2" or Option == "se": F_SE()
    elif Option == "3" or Option == "ae": F_AE()
    elif Option == "4" or Option == "encoding": F_Encoding()
    elif Option == "5" or Option == "hash": F_Hash()
    elif Option == "6" or Option == "random": F_Random()
    elif Option == "7" or Option == "storage": F_Storage()
    elif Option == "!" or Option == "exit":
        print(THEMECOLOR + "Exiting program...")
        time.sleep(1.0)
        colorama.deinit()
        return

    elif Option == "cls":
        Shell_Reset()

    elif Option == "ls":
        global Program_Directory

        print(THEMECOLOR)
        Path = input("Path: ")
        print("")

        if Path == "root":
            Path = Program_Directory

        Extension_Dictionary = [
            ".txt",
            ".md",
            ".pdf",
            ".vtxc",
            ".vsfp",
            ".vpv",
        ]
        try:
            for File in os.listdir(Path):
                for Extension in Extension_Dictionary:
                    if File.endswith(Extension):
                        print(LIGHTYELLOW + os.path.join(Path, File) + THEMECOLOR)
        except NotADirectoryError:
            print(LIGHTRED + "Error: Ensure that the path is to a folder or directory, not a file." + THEMECOLOR)
        F_Main()

    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_Main()

#################### - Theme - ####################

def F_Theme_Configure():
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/F_Theme_Configure      |
------------------------------------------'''
    print(Function_Header)
    Option_Confirm = input("Edit (Theme.ini)? (y/n) ")

    if Option_Confirm == "y": F_Theme_Write()
    elif Option_Confirm == "n": F_Main()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_Main()

def F_Theme_Write():
    print(THEMECOLOR)
    print("- Edit (Theme.ini) -")

    VOD = \
'''

WHITE
LIGHTCYAN
LIGHTMAGENTA
LIGHTBLUE
LIGHTYELLOW
LIGHTGREEN
LIGHTRED
DARKGREY
LIGHTGREY
CYAN
MAGENTA
BLUE
YELLOW
GREEN
BLACK
DEFAULT
RED\
'''
    print(VOD + LIGHTYELLOW)
    print(THEMECOLOR)
    Theme_Input = input("Theme Color: ")
    try:
        with open("Theme.ini", "w") as Theme_File:
            Theme_File.writelines(Theme_Input)
            Theme_File.close()
        print("Wrote color option '%s' to (Theme.ini)." % (Theme_Input))
        input("Press 'Enter' to continue... ")
        F_Main()
    except FileNotFoundError:
        print(LIGHTRED + "Error: Initial theme configuration file 'Theme.ini' not found." + THEMECOLOR)
        time.sleep(1.0)
        F_Main()

#################### - Symmetric Encryption - ####################

def F_SE():
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/F_SE                   |
------------------------------------------'''
    print(Function_Header)
    VOD = \
'''\
1: AES
!: Back\
'''
    print(VOD + LIGHTYELLOW)
    Option_SE = input("")

    if Option_SE == "1": F_SE_AES()
    elif Option_SE == "!" or Option_SE == "back": F_Main()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_SE()

def F_SE_AES():
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/F_SE_AES               |
------------------------------------------'''
    print(Function_Header)
    VOD = \
'''\
1: File (VSFP)
2: String (VTXC)
3: Help
!: Back\
'''
    print(VOD + LIGHTYELLOW)
    Option_AES = input("")

    if Option_AES == "1": F_SE_AES_Gate_File()
    elif Option_AES == "2": F_SE_AES_Gate_String()
    elif Option_AES == "3":
        global AES_Help
        print(AES_Help)
        F_SE_AES()

    elif Option_AES == "!" or Option_AES == "back": F_Main()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_SE_AES()

def F_SE_AES_Gate_File():
    print(THEMECOLOR)
    print("- Symmetric Encryption (File) -")
    VOD = \
'''\
1: Encrypt
2: Decrypt
!: Back\
'''
    print(VOD + LIGHTYELLOW)
    Option = input("")

    if Option == "1": F_SE_AES_Encrypt_File()
    elif Option == "2": F_SE_AES_Decrypt_File()
    elif Option == "!" or Option == "back": F_SE_AES()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_SE_AES()

def F_SE_AES_Encrypt_File():
    pass

def F_SE_AES_Decrypt_File():
    pass

def F_SE_AES_Gate_String():
    print(THEMECOLOR)
    print("- Symmetric Encryption (String) -")
    VOD = \
'''\
1: Encrypt
2: Decrypt
!: Back\
'''
    print(VOD + LIGHTYELLOW)
    Option = input("")

    # - Encrypt
    if Option == "1":
        print(THEMECOLOR)
        print("- AES: String (Encrypt) -")
        Option_Import = input("Import data from file? (y/n) ")

        if Option_Import == "y":
            try:
                File_Import = input("File Import: ")
                with open(File_Import, "r") as File:
                    Data = File.readlines()
                    Split = "\n"
                    Plaintext = Split.join(Data)
                File.close()

                Password = input("Password: ")

                # - Key_Size
                VOD = \
'''\
1: AES-128
2: AES-192
3: AES-256\
'''
                print(VOD + LIGHTYELLOW)
                Key_Size = input("")
            except FileNotFoundError:
                print(LIGHTRED + "Error: No such file exists." + THEMECOLOR)
                F_SE_AES_Gate_String()

        elif Option_Import == "n":
            print("After all lines have been input, type '--END--' to close the loop.")
            print("Plaintext:")
            Lines = []
            End = "--END--"
            while True:
                Line = input("")
                if End in Line:
                    break
                else:
                    Lines.append(Line)
            Plaintext = "\n".join(Lines)
            Password = input("Password: ")

            # - Key_Size
            VOD = \
'''\
1: AES-128
2: AES-192
3: AES-256\
'''
            print(VOD + LIGHTYELLOW)
            Key_Size = input("")

        else:
            print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
            time.sleep(1.0)
            F_SE_AES()

        F_SE_AES_Encrypt_String(plaintext=Plaintext, password=Password, key_size=Key_Size)

    # - Decrypt
    elif Option == "2":
        print(THEMECOLOR)
        print("- AES: String (Decrypt) -")
        Option_Import = input("Import data from file? (y/n) ")

        if Option_Import == "y":
            try:
                File_Import = input("File Import: ")
                with open(File_Import, "r") as File:
                    Salt = File.readline()
                    IV = File.readline()
                    Data = File.readlines()
                    Split = "\n"
                    Ciphertext = Split.join(Data)
                File.close()

                Password = input("Password: ")

                # - Key_Size
                VOD = \
'''\
1: AES-128
2: AES-192
3: AES-256\
'''
                print(VOD + LIGHTYELLOW)
                Key_Size = input("")
            except FileNotFoundError:
                print(LIGHTRED + "Error: No such file exists." + THEMECOLOR)
                F_SE_AES_Gate_String()

        elif Import_Option == "n":
            Plaintext = input("Plaintext: ")
            Password = input("Password: ")

            # - Key_Size
            VOD = \
'''\
1: AES-128
2: AES-192
3: AES-256\
'''
            print(VOD + LIGHTYELLOW)
            Key_Size = input("")

        else:
            print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
            time.sleep(1.0)
            F_SE_AES()

        F_SE_AES_Decrypt_String(ciphertext = Ciphertext, iv = IV, password = str(Password), salt = Salt, key_size = Key_Size)

    # - Back
    elif Option == "!" or Option == "back": F_SE_AES()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_SE_AES()

def F_SE_AES_Encrypt_String(plaintext, password, key_size):
        Plaintext_Byte = plaintext.encode()
        Plaintext_Byte_Pad = pad(Plaintext_Byte, AES.block_size)
        # The encoded input data is padded to fit the AES block size (16-Byte).

        # ------------------------------------------------------ #
        # KDF:
        if key_size == "1": Key_Length = 16
        elif key_size == "2": Key_Length = 24
        elif key_size == "3": Key_Length = 32
        else:
            print(LIGHTRED + "Error: Invalid key size option." + THEMECOLOR)
            time.sleep(1.0)
            F_SE_AES_Gate_String()

        Salt = get_random_bytes(16)
        Key = scrypt(password, Salt, Key_Length, N=2**20, r=8, p=1)
        # - ( 2¹⁴, 8, 1 ) for interactive logins (≤100ms)
        # - ( 2²⁰, 8, 1 ) for file encryption (≤5s)
        # ------------------------------------------------------ #

        # IV: An "initialization vector" is a 16-Byte randomly generated string that randomizes the digest for ciphertext generation, similar to a seed.
        # 16-Byte Key (128-bit)
        # 24-Byte Key (192-bit)
        # 32-Byte Key (256-bit)

        Cipher = AES.new(Key, AES.MODE_CBC)
        Ciphertext = Cipher.encrypt(Plaintext_Byte_Pad)

        Base64_Salt = base64.encodebytes(Salt).rstrip()
        Base64_IV = base64.encodebytes(Cipher.iv).rstrip()
        Base64_Ciphertext = base64.encodebytes(Ciphertext).rstrip()

        print(THEMECOLOR)
        print("- Output (Encrypt) -")
        print(LIGHTGREEN + "Password Salt:" + "\n" + LIGHTYELLOW + Base64_Salt.decode() + THEMECOLOR)
        print(LIGHTGREEN + "Cipher Vector:" + "\n" + LIGHTYELLOW + Base64_IV.decode() + THEMECOLOR)
        print(LIGHTGREEN + "Ciphertext:" + "\n" + LIGHTYELLOW + Base64_Ciphertext.decode() + THEMECOLOR)

        Save_Option = input("Save the encrypted data to a file (*.vtxc, *.txt)? (y/n) ")
        if Save_Option == "y":
            File_Export = input("File Export: ")
            F_SE_AES_Save_String(file_path=File_Export, salt=Base64_Salt.decode(), iv=Base64_IV.decode(), ciphertext=Base64_Ciphertext.decode())
            F_SE_AES_Gate_String()

        elif Save_Option == "n": F_SE_AES_Gate_String()
        else:
            print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
            time.sleep(1.0)
            F_SE_AES_Gate_String()

def F_SE_AES_Decrypt_String(ciphertext, iv, password, salt, key_size):
    try:
        Ciphertext = base64.b64decode(ciphertext)
        IV = base64.b64decode(iv)
        Salt = base64.b64decode(salt)

        # ------------------------------------------------------ #
        # Reverse KDF:
        if key_size == "1": Key_Length = 16
        elif key_size == "2": Key_Length = 24
        elif key_size == "3": Key_Length = 32
        else:
            print(LIGHTRED + "Error: Invalid key size option." + THEMECOLOR)
            time.sleep(1.0)
            F_SE_AES_Gate_String()

        Key = scrypt(password, Salt, Key_Length, N=2**20, r=8, p=1)
        # ------------------------------------------------------ #

        Cipher = AES.new(Key, AES.MODE_CBC, IV)

        Plaintext = Cipher.decrypt(Ciphertext)
        Plaintext = unpad(Plaintext, AES.block_size)

        print(THEMECOLOR)
        print("- Output (Decrypt) -")
        print(LIGHTGREEN + "Plaintext:" + "\n" + LIGHTYELLOW + Plaintext.decode() + THEMECOLOR)
        F_SE_AES_Gate_String()
    except ValueError:
        print(LIGHTRED + "Error: Incorrect password." + THEMECOLOR)
        time.sleep(1.0)
        F_SE_AES_Gate_String()

def F_SE_AES_Save_String(file_path, salt, iv, ciphertext):
    Vortex_Extension = ".vtxc"

    if file_path.endswith(Vortex_Extension):
        with open(file_path, "w") as File:
            File.writelines(salt + "\n")
            File.writelines(iv + "\n")
            File.writelines(ciphertext)
            File.close()

    else:
        with open(File_Path, "w") as File:
            File.writelines(ciphertext)
            File.close()

#################### - Asymmetric Encryption - ####################

def F_AE():
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/F_AE                   |
------------------------------------------'''
    print(Function_Header)
    VOD = \
'''\
1: RSA
2: PGP
3: DSA
!: Back\
'''
    print(VOD + LIGHTYELLOW)
    Option_AE = input("")

    if Option_AE == "1": F_AE_RSA()

    elif Option_AE == "2" or Option_AE == "3":
        print(LIGHTRED + "Error: This feature is not available yet." + THEMECOLOR)
        time.sleep(1.0)
        F_AE()

    elif Option_AE == "!" or Option_AE == "back": F_Main()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_AE()

def F_AE_RSA():
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/F_AE_RSA               |
------------------------------------------'''
    print(Function_Header)
    VOD = \
'''\
1: Encrypt
2: Decrypt
3: Key Manager
!: Back\
'''
    print(VOD + LIGHTYELLOW)
    Option_AE_RSA = input("")

    if Option_AE_RSA == "1": pass
    elif Option_AE_RSA == "2": pass
    elif Option_AE_RSA == "3": F_AE_RSA_Key()
    elif Option_AE_RSA == "!" or Option_AE_RSA == "back": F_AE()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_AE()

def F_AE_RSA_Key():
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/F_AE_RSA_Key           |
------------------------------------------'''
    print(Function_Header)
    VOD = \
'''\
1: Generate Key Pair
!: Back\
'''
    print(VOD + LIGHTYELLOW)
    Option_Key = input("")

    if Option_Key == "1":
        print(THEMECOLOR)
        print("- Generate Key Pair -")

        VOD = \
'''\
1: RSA-1024
2: RSA-2048
3: RSA-4096\
'''
        print(VOD + LIGHTYELLOW)

        Option_Length = input("")

        if Option_Length == "1":
            print(THEMECOLOR + "Generating key pair with length (1024)...")
            Key = RSA.generate(1024)
            Key_Private = Key.export_key()
            Key_Public = Key.publickey().export_key()
            print(THEMECOLOR)
            print("- Output (Generate Key Pair) -")
            print(LIGHTGREEN + "Private Key (1024):" + "\n" + LIGHTYELLOW, Key_Private, THEMECOLOR)
            print("")
            print(LIGHTGREEN + "Public Key (1024):" + "\n" + LIGHTYELLOW, Key_Public, THEMECOLOR)
            F_AE_RSA_Key()

        elif Option_Length == "2":
            print(THEMECOLOR + "Generating key pair with length (2048)...")
            Key = RSA.generate(2048)
            Key_Private = Key.export_key()
            Key_Public = Key.publickey().export_key()
            print(THEMECOLOR)
            print("- Output (Generate Key Pair) -")
            print(LIGHTGREEN + "Private Key (2048):" + "\n" + LIGHTYELLOW, Key_Private, THEMECOLOR)
            print("")
            print(LIGHTGREEN + "Public Key (2048):" + "\n" + LIGHTYELLOW, Key_Public, THEMECOLOR)
            F_AE_RSA_Key()

        if Option_Length == "3":
            print(THEMECOLOR + "Generating key pair with length (4096)...")
            Key = RSA.generate(4096)
            Key_Private = Key.export_key()
            Key_Public = Key.publickey().export_key()
            print(THEMECOLOR)
            print("- Output (Generate Key Pair) -")
            print(LIGHTGREEN + "Private Key (4096):" + "\n" + LIGHTYELLOW, Key_Private, THEMECOLOR)
            print("")
            print(LIGHTGREEN + "Public Key (4096):" + "\n" + LIGHTYELLOW, Key_Public, THEMECOLOR)
            F_AE_RSA_Key()

        else:
            print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
            time.sleep(1.0)
            F_AE_RSA_Key()

    elif Option_Key == "!" or Option_Key == "back": F_AE_RSA()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_AE()

#################### - Encoding Module - ####################

def F_Encoding():
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/F_Encoding             |
------------------------------------------'''
    print(Function_Header)
    VOD = \
'''\
1: UTF-8
2: UTF-16
3: Base16
4: Base32
5: Base64
6: Vortexian Braille (VTXE-B)
!: Back\
'''
    print(VOD + LIGHTYELLOW)
    Option = input("")

# - Base16

    if Option == "3":
        print(THEMECOLOR)
        print("- Encode (Base16) -")
        try:
            VOD = \
'''\
1: Encode
2: Decode\
'''
            print(VOD)
            Mode = int(input("Mode: "))
            if Mode == 1:
                Data = input("Data: ")
                Data = Data.encode()
                Result = base64.b16encode(Data)
                print(THEMECOLOR)
                print("- Output (Encode, Base16) -")
                print(Result)
                F_Encoding()

            elif Mode == 2:
                Data = input("Data: ")
                Result = base64.b16decode(Data)
                print(THEMECOLOR)
                print("- Output (Decode, Base16) -")
                print(Result.decode())
                F_Encoding()

        except ValueError:
            print(LIGHTRED + "Error: One or more invalid arguments." + THEMECOLOR)
            time.sleep(1.0)
            F_Encoding()

# - Base32

    elif Option == "4":
        print(THEMECOLOR)
        print("- Encode (Base32) -")
        try:
            VOD = \
'''\
1: Encode
2: Decode\
'''
            print(VOD)
            Mode = int(input("Mode: "))
            if Mode == 1:
                Data = input("Data: ")
                Data = Data.encode()
                Result = base64.b32encode(Data)
                print(THEMECOLOR)
                print("- Output (Encode, Base32) -")
                print(Result)
                F_Encoding()

            elif Mode == 2:
                Data = input("Data: ")
                Result = base64.b32decode(Data)
                print(THEMECOLOR)
                print("- Output (Decode, Base32) -")
                print(Result.decode())
                F_Encoding()

        except ValueError:
            print(LIGHTRED + "Error: One or more invalid arguments." + THEMECOLOR)
            time.sleep(1.0)
            F_Encoding()

# - Base64

    elif Option == "5":
        print(THEMECOLOR)
        print("- Encode (Base64) -")
        # try:
        VOD = \
'''\
1: Encode
2: Decode\
'''
        print(VOD)
        Mode = int(input("Mode: "))
        if Mode == 1:
            Data = input("Data: ")
            Data = Data.encode()
            Result = base64.encodebytes(Data)
            print(THEMECOLOR)
            print("- Output (Encode, Base64) -")
            print(Result)
            F_Encoding()

        elif Mode == 2:
            Data = input("Data: ")
            Data = Data.encode()
            Result = base64.decodebytes(Data)
            print(THEMECOLOR)
            print("- Output (Decode, Base64) -")
            print(Result.decode())
            F_Encoding()

        # except ValueError:
        #     print(LIGHTRED + "Error: One or more invalid arguments." + THEMECOLOR)
        #     time.sleep(1.0)
        #     F_Encoding()

# - VTXE-B

    elif Option == "6":
        print(THEMECOLOR)
        print("- Encode (VTXE-B) -")
        try:
            VOD = \
'''\
1: Encode
2: Decode\
'''
            print(VOD)
            Mode = int(input("Mode: "))
            Data = input("Data: ")
            VTXE_B(data=Data, mode=Mode)
        except ValueError:
            print(LIGHTRED + "Error: One or more invalid arguments." + THEMECOLOR)
            time.sleep(1.0)
            F_Encoding()

    elif Option == "!" or Option == "back": F_Main()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_Encoding()

def VTXE_B(data, mode):
    # 1: Encode
    # 2: Decode
    if mode == 1:
        data = data.upper()
        data = data.replace("'", "")
        data = data.replace("-", "")
        data = data.replace("=", "")
        data = data.replace("+", "")
        data = data.replace("_", "")
        data = data.replace("!", "")
        data = data.replace("@", "")
        data = data.replace("#", "")
        data = data.replace("$", "")
        data = data.replace("%", "")
        data = data.replace("^", "")
        data = data.replace("&", "")
        data = data.replace("*", "")
        data = data.replace("(", "")
        data = data.replace(")", "")
        data = data.replace("/", "")
        data = data.replace("\\", "")
        data = data.replace("|", "")
        data = data.replace("[", "")
        data = data.replace("]", "")
        data = data.replace("?", "")
        data = data.replace(".", "")
        data = data.replace(",", "")
        data = data.replace(":", "")
        data = data.replace(";", "")
        data = data.replace("`", "")
        data = data.replace("~", "")
        data = data.replace('"', "")

        Data_Init = list(data)
        Data_New = []

        for Letter in Data_Init:
            if Letter == "A": Letter = "."
            elif Letter == "B": Letter = ".,"
            elif Letter == "C": Letter = ".,."
            elif Letter == "D": Letter = "::"
            elif Letter == "E": Letter = ":':"
            elif Letter == "F": Letter = ":;:"
            elif Letter == "G": Letter = "':':'"
            elif Letter == "H": Letter = ";',,';"
            elif Letter == "I": Letter = ";''.'';"
            elif Letter == "J": Letter = "~"
            elif Letter == "K": Letter = "~."
            elif Letter == "L": Letter = "~.,"
            elif Letter == "M": Letter = "~.,."
            elif Letter == "N": Letter = "~::"
            elif Letter == "O": Letter = "~:':"
            elif Letter == "P": Letter = "~:;:"
            elif Letter == "Q": Letter = "~':':'"
            elif Letter == "R": Letter = "~;',,';"
            elif Letter == "S": Letter = "~;''.'';"
            elif Letter == "T": Letter = "~~"
            elif Letter == "U": Letter = "~~."
            elif Letter == "V": Letter = "~~.,"
            elif Letter == "W": Letter = "~~.,."
            elif Letter == "X": Letter = "~~::"
            elif Letter == "Y": Letter = "~~:':"
            elif Letter == "Z": Letter = "~~:;:"
            elif Letter == " ": Letter = "    "
            Data_New.append(Letter)

        Result = "|".join(Data_New)
        Result = "|" + Result + "|"
        print(THEMECOLOR)
        print("- Output (Encode, VTXE-B) -")
        print(Result)
        F_Encoding()

    elif mode == 2:
        Data = data
        Data = Data.replace("|.|", "|A|")
        Data = Data.replace("|.,|", "|B|")
        Data = Data.replace("|.,.|", "|C|")
        Data = Data.replace("|::|", "|D|")
        Data = Data.replace("|:':|", "|E|")
        Data = Data.replace("|:;:|", "|F|")
        Data = Data.replace("|':':'|", "|G|")
        Data = Data.replace("|;',,';|", "|H|")
        Data = Data.replace("|;''.'';|", "|I|")
        Data = Data.replace("|~|", "|J|")
        Data = Data.replace("|~.|", "|K|")
        Data = Data.replace("|~.,|", "|L|")
        Data = Data.replace("|~.,.|", "|M|")
        Data = Data.replace("|~::|", "|N|")
        Data = Data.replace("|~:':|", "|O|")
        Data = Data.replace("|~:;:|", "|P|")
        Data = Data.replace("|~':':'|", "|Q|")
        Data = Data.replace("|~;',,';|", "|R|")
        Data = Data.replace("|~;''.'';|", "|S|")
        Data = Data.replace("|~~|", "|T|")
        Data = Data.replace("|~~.|", "|U|")
        Data = Data.replace("|~~.,|", "|V|")
        Data = Data.replace("|~~.,.|", "|W|")
        Data = Data.replace("|~~::|", "|X|")
        Data = Data.replace("|~~:':|", "|Y|")
        Data = Data.replace("|~~:;:|", "|Z|")
        Data = Data.replace("    ", " ")
        Data = Data.replace("|", "")
        Result = Data

        print(THEMECOLOR)
        print("- Output (Decode, VTXE-B) -")
        print(Result)
        F_Encoding()

#################### - Hash Module - ####################

def F_Hash():
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/F_Hash                 |
------------------------------------------'''
    print(Function_Header)
    VOD = \
'''\
1: Generate Hash
2: Create Rainbow Table
!: Back\
'''
    print(VOD + LIGHTYELLOW)
    Option = input("")

    if Option == "1":
        print(THEMECOLOR)
        print("- Generate Hash -")

        try:
            Data = input("Data: ")

            VOD = '''
1: MD2
2: MD4
3: MD5
4: SHA-1
5: SHA-256
6: SHA-512
7: SHA3-256
8: SHA3-512\
'''
            print("Available Hash Functions:" + VOD)
            Option_Function = input("Hash Function: ")

            # Layers = int(input("Layers: "))
            F_Hash_Generate(data=Data, function=Option_Function, layers=1)
        except ValueError:
            print(LIGHTRED + "Error: One or more invalid arguments." + THEMECOLOR)
            time.sleep(1.0)
            F_Hash()

    elif Option == "2":
        print(THEMECOLOR)
        print("- Create Rainbow Table -")
        F_Rainbow()

    elif Option == "!" or Option == "back": F_Main()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_Hash()

def F_Hash_Generate(data, function, layers):
    try:
        # Hash_Label = str(Function)[1:-20]
        # Hash_Label = Hash_Label.replace("Crypto.Hash.", "")
        # Hash_Label = Hash_Label.replace("object at", "")
        # Hash_Label = Hash_Label.rstrip()

        Process_Begin = time.time()

        # - Note to self: try a nested for loop.
        # for i in range(layers):
        #     Digest = str(function.hexdigest())
        #     data = Digest

        if function == "1":
            Function = MD2.new(data=data.encode())
            Hash_Label = "MD2"

        elif function == "2":
            Function = MD4.new(data=data.encode())
            Hash_Label = "MD4"

        elif function == "3":
            Function = MD5.new(data=data.encode())
            Hash_Label = "MD5"

        elif function == "4":
            Function = SHA1.new(data=data.encode())
            Hash_Label = "SHA-1"

        elif function == "5":
            Function = SHA256.new(data=data.encode())
            Hash_Label = "SHA-256"

        elif function == "6":
            Function = SHA512.new(data=data.encode())
            Hash_Label = "SHA-512"

        elif function == "7":
            Function = SHA3_256.new(data=data.encode())
            Hash_Label = "SHA3-256"

        elif function == "8":
            Function = SHA3_512.new(data=data.encode())
            Hash_Label = "SHA3-512"

        Digest = str(Function.hexdigest())

        print(LIGHTGREEN + "Hash Function: {0} | Layers: {1} | Digest:".format(Hash_Label, layers) + "\n" + LIGHTYELLOW + Digest + THEMECOLOR)

        Process_End = time.time()
        Process_Time = (Process_End - Process_Begin)
        Result = str(Process_Time)[:-10]
        print("Processed in %s seconds!" % (Result))

        F_Hash()
    except UnboundLocalError:
        print(LIGHTRED + "Error: 'layer' argument cannot be zero." + THEMECOLOR)
        time.sleep(1.0)
        F_Hash()

def F_Rainbow():
    File = input("File: ")
    Lines = int(input("Lines: "))
    VOD = '''
1: MD2
2: MD4
3: MD5
4: SHA-1
5: SHA-256
6: SHA-512
7: SHA3-256
8: SHA3-512\
'''
    print("Available Hash Functions:" + VOD)
    Option_Function = input("Hash Function: ")

    if Option_Function == "1": Function = MD2
    elif Option_Function == "2": Function = MD4
    elif Option_Function == "3": Function = MD5
    elif Option_Function == "4": Function = SHA1
    elif Option_Function == "5": Function = SHA256
    elif Option_Function == "6": Function = SHA512
    elif Option_Function == "7": Function = SHA3_256
    elif Option_Function == "8": Function = SHA3_512
    Separator = input("Separator: ")
    Append_Front = input("Append hash to the end of each line (defaults to the front)? (y/n) ")
    if Append_Front == "y":
        Append_Front = False
    elif Append_Front == "n":
        Append_Front = True
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_Rainbow()
    F_Rainbow_Generate(file=File, lines=Lines, function=Function, separator=Separator, append_front=Append_Front)

def F_Rainbow_Generate(file, lines, function, separator, append_front: True):
    try:
        with open(file, "r+") as File:
            for i in range(lines):
                line = File.readline()
                Hash = function.new(data=line.encode())
                Digest = Hash.hexdigest()
                if append_front == True:
                    File.write(Digest + " " + separator + " " + line + "\n")
                else:
                    File.write(line + " " + separator + " " + Digest + "\n")
            File.close()

    except FileNotFoundError:
        print(LIGHTRED + "Error: No such file exists." + THEMECOLOR)
        time.sleep(1.0)
        F_Rainbow()

#################### - Random Module - ####################

def F_Random():
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/F_Random               |
------------------------------------------'''
    print(Function_Header)
    VOD = \
'''\
1: String
2: Bytes
3: Number
4: Choice
!: Back\
'''
    print(VOD + LIGHTYELLOW)
    Option = input("")

    if Option == "1": F_Random_Gate_String()
    elif Option == "2": F_Random_Gate_Bytes()
    elif Option == "3": F_Random_Gate_Number()
    elif Option == "4": F_Random_Gate_Choice()
    elif Option == "!" or Option == "back": F_Main()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_Random()

def F_Random_Gate_String():
    print(THEMECOLOR)
    print("- Random String -")
    VOD = \
'''\
1: Letters (Default)
2: Numbers
3: Letters + Numbers
%s4: Alphanumeric (Secure)%s\
''' % (LIGHTYELLOW, THEMECOLOR)
    print(VOD + LIGHTYELLOW)
    Option = input("")

    if Option == "1": # Letters (Default)
        print(THEMECOLOR)
        Count = input("Count: ")
        Length = input("String Length: ")
        F_Random_String(count = int(Count), length = int(Length), mode = 1)

    elif Option == "2": # Numbers
        print(THEMECOLOR)
        Count = input("Count: ")
        Length = input("String Length: ")
        F_Random_String(count = int(Count), length = int(Length), mode = 2)

    elif Option == "3": # Letters + Numbers
        print(THEMECOLOR)
        Count = input("Count: ")
        Length = input("String Length: ")
        F_Random_String(count = int(Count), length = int(Length), mode = 3)

    elif Option == "4": # Alphanumeric (Secure)
        print(THEMECOLOR)
        Count = input("Count: ")
        Length = input("String Length: ")
        F_Random_String(count = int(Count), length = int(Length), mode =4)

    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_Random()

def F_Random_String(count, length, mode = 1):
    print(THEMECOLOR)
    if mode == 1: # Letters (Default)
        print("- Random String (Letters) -")
        String_Characters = string.ascii_letters
        for i in range(count):
            String = ''.join(secrets.choice(String_Characters) for i in range(length))
            print(LIGHTGREEN + "String:" + "\n" + LIGHTYELLOW + String + THEMECOLOR)

    elif mode == 2: # Numbers
        print("- Random String (Numbers) -")
        String_Characters = string.digits
        for i in range(count):
            String = ''.join(secrets.choice(String_Characters) for i in range(length))
            print(LIGHTGREEN + "String:" + "\n" + LIGHTYELLOW + String + THEMECOLOR)

    elif mode == 3: # Letters + Numbers
        print("- Random String (Letters + Numbers) -")
        String_Characters = string.ascii_letters + string.digits
        for i in range(count):
            String = ''.join(secrets.choice(String_Characters) for i in range(length))
            print(LIGHTGREEN + "String:" + "\n" + LIGHTYELLOW + String + THEMECOLOR)

    elif mode == 4: # Alphanumeric (Secure)
        print("- Random String (Alphanumeric) -")
        String_Characters = string.ascii_letters + string.digits + string.punctuation
        for i in range(count):
            String = ''.join(secrets.choice(String_Characters) for i in range(length))
            print(LIGHTGREEN + "String:" + "\n" + LIGHTYELLOW + String + THEMECOLOR)

    F_Random()

def F_Random_Gate_Bytes():
    print(THEMECOLOR)
    print("- Random Bytes -")
    VOD = \
'''\
1: Default
%s2: Secure%s\
''' % (LIGHTYELLOW, THEMECOLOR)
    print(VOD + LIGHTYELLOW)
    Option = input("")

    if Option == "1":
        print(THEMECOLOR)
        Count = input("Count: ")
        Length = input("Array Length: ")
        F_Random_Bytes(count = int(Count), length = int(Length), mode = 1)

    elif Option == "2":
        print(THEMECOLOR)
        Count = input("Count: ")
        Length = input("Array Length: ")
        F_Random_Bytes(count = int(Count), length = int(Length), mode = 2)

    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_Random()

def F_Random_Bytes(count, length, mode = 1):
    print(THEMECOLOR)
    if mode == 1: # Default
        print("- Random Bytes (Default) -")
        for i in range(count):
            Output = os.urandom(int(length))
            print(LIGHTGREEN + "Bytes:" + "\n" + LIGHTYELLOW + str(Output) + THEMECOLOR)
    
    if mode == 2: # Secure
        print("- Random Bytes (Secure) -")
        for i in range(count):
            Output = get_random_bytes(int(length))
            print(LIGHTGREEN + "Bytes:" + "\n" + LIGHTYELLOW + str(Output) + THEMECOLOR)
    F_Random()

def F_Random_Gate_Number():
    print(THEMECOLOR)
    print("- Random Number -")
    VOD = \
'''\
1: Default (X => Y)
%s2: Secure (0 => Y)%s\
''' % (LIGHTYELLOW, THEMECOLOR)
    print(VOD + LIGHTYELLOW)
    Option = input("")

    if Option == "1": # Default
        print(THEMECOLOR)
        Count = input("Count: ")
        Count = int(Count)
        Min = input("Minimum #: ")
        Max = input("Maximum #: ")
        F_Random_Number(count = Count, min = Min, max = Max, mode = 1)

    elif Option == "2": # Secure
        print(THEMECOLOR)
        Count = input("Count: ")
        Count = int(Count)
        Max = input("Maximum #: ")
        F_Random_Number(count = Count, min = 0, max = Max, mode =2)

    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_Random()

def F_Random_Number(count, min, max, mode = 1):
    print(THEMECOLOR)
    if mode == 1:
        try:
            print("- Random Number (Default) -")
            for i in range(count):
                print(LIGHTYELLOW + str(random.randint(int(min),int(max))) + THEMECOLOR)
        except ValueError:
            print(LIGHTRED + "Error: Maximum number must be positive." + THEMECOLOR)
            time.sleep(1.0)
            F_Random()

    elif mode == 2:
        try:
            print("- Random Number (Secure) -")
            for i in range(count):
                print(LIGHTYELLOW + str(secrets.randbelow(int(max))) + THEMECOLOR)
        except ValueError:
            print(LIGHTRED + "Error: Maximum number must be positive." + THEMECOLOR)
            time.sleep(1.0)
            F_Random()

    F_Random()

def F_Random_Gate_Choice():
    print(THEMECOLOR)
    print("- Random Choice -")
    VOD = \
'''\
1: Default
%s2: Secure%s\
''' % (LIGHTYELLOW, THEMECOLOR)
    print(VOD + LIGHTYELLOW)
    Option = input("")

    if Option == "1": # Default
        print(THEMECOLOR)
        File = input("File: ")
        Count = input("Count: ")
        F_Random_Choice(file = File, count = int(Count), mode = 1)

    elif Option == "2": # Secure
        print(THEMECOLOR)
        File = input("File: ")
        Count = input("Count: ")
        F_Random_Choice(file = File, count = int(Count), mode = 2)

    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_Random()

def F_Random_Choice(file, count, mode = 1):
    print(THEMECOLOR)
    if mode == 1:
        print("- Random Choice (Default) -")
        try:
            with open(file, "r") as File:
                Lines = File.readlines()

            for i in range(count):
                Choice = random.choice(Lines)
                Choice = Choice.rstrip()
                print(LIGHTGREEN + "Choice:\n" + LIGHTYELLOW + Choice + THEMECOLOR)
            F_Random()
        except FileNotFoundError:
            print(LIGHTRED + "Error: No such file exists." + THEMECOLOR)
            time.sleep(1.0)
            F_Random()

    elif mode == 2:
        print("- Random Choice (Secure) -")
        try:
            with open(file, "r") as File:
                Lines = File.readlines()

            for i in range(count):
                Choice = secrets.choice(Lines)
                Choice = Choice.rstrip()
                print(LIGHTGREEN + "Choice:\n" + LIGHTYELLOW + Choice + THEMECOLOR)
            F_Random()
        except FileNotFoundError:
            print(LIGHTRED + "Error: No such file exists." + THEMECOLOR)
            time.sleep(1.0)
            F_Random()

    F_Random()

def F_Storage():
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/F_Storage              |
------------------------------------------'''
    print(Function_Header)
    VOD = \
'''\
1: Secure Delete (VTXP-SECDEL)
!: Back\
'''
    print(VOD + LIGHTYELLOW)
    Option = input("")

    if Option == "1":
        print(THEMECOLOR)
        File_Path = input("Path: ")

        VOD = \
'''\
1: Kilobytes
2: Megabytes
3: Gigabytes\
'''
        print(VOD)
        Data_Mode = int(input(""))
        if Data_Mode == 1: Type = "KB"
        elif Data_Mode == 2: Type = "MB"
        elif Data_Mode == 3: Type = "GB"

        Data_Size = int(input("File Size ({}): ".format(Type)))
        File_Passes = int(input("Passes: "))
        Confirmation = input("Confirm delete? (y/n) ")
        if Confirmation == "y": F_SECDEL(file_path = File_Path, data_size = Data_Size, file_passes = File_Passes, data_mode = Data_Mode)
        else: F_Storage()

    elif Option == "!" or Option == "back": F_Main()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_Storage()

def F_SECDEL(file_path : str, data_size : int, file_passes : int, data_mode = 1):
    print(THEMECOLOR)
    print("- Vortex SECDEL Protocol -")
    try:
        with open(file_path, "w") as File:
            Process_Begin = time.time()
            for i in range(file_passes):

                if data_mode == 1: # - Kilobytes
                    Size = data_size * 1024

                elif data_mode == 2: # - Megabytes
                    Size = data_size * 1048576

                elif data_mode == 3: # - Gigabytes
                    Size = data_size * 1073741824

                Bytes = string.ascii_letters
                Data = ''.join(secrets.choice(Bytes) for i in range(Size))

                File.write(Data)
                print("{}Wrote {}{}{} bytes of data to {}{}{}...{}".format(LIGHTGREEN, LIGHTYELLOW, Size, LIGHTGREEN, LIGHTYELLOW, file_path, LIGHTGREEN, THEMECOLOR))

            File.close()

            Process_End = time.time()
            Process_Time = (Process_End - Process_Begin)

            Result = str(Process_Time)[:-10]
            print("Processed in %s seconds!" % (Result))
            F_Storage()

    except FileNotFoundError:
        print(LIGHTRED + "Error: No such file exists." + THEMECOLOR)
        time.sleep(1.0)
        F_Storage()

# def F_AE_RSA_Encrypt():
#     Plaintext = InputText_RSA.get("1.0", "end").rstrip()
#     Plaintext = Plaintext.encode("utf-8")
#     RSA_Key = RSA.import_key(KeyEntry_RSA.get("1.0", "end"))
#     Session_Key = get_random_bytes(16)

#     # The AES "session key" is encrypted using the RSA key.
#     Cipher_RSA = PKCS1_OAEP.new(RSA_Key)
#     Session_Key_Encrypted = Cipher_RSA.encrypt(Session_Key)

#     Cipher_AES = AES.new(Session_Key, AES.MODE_EAX)

#     Ciphertext, Tag = Cipher_AES.encrypt_and_digest(Plaintext)

#     OutputText_RSA.delete(1.0, "end")
#     [ OutputText_RSA.insert(1.0, Ciphertext) for Ciphertext in (Session_Key_Encrypted, Cipher_AES.nonce, Tag, Ciphertext) ]
#     OutputText_RSA.bind("<Key>", lambda a: "break")

# def F_AE_RSA_Decrypt():
#     # try:
#         Data = InputText_RSA.get("1.0", "end")
#         RSA_Key = RSA.importKey(KeyEntry_RSA.get("1.0", "end"))

#         Session_Key_Encrypted, Nonce, Tag, Ciphertext = \
#             [ Data for Data in (RSA_Key.size_in_bytes(), 16, 16, -1) ]

#         # The AES "session key" is decrypted using the RSA key.
#         Cipher_RSA = PKCS1_OAEP.new(RSA_Key)
#         Session_Key = Cipher_RSA.decrypt(Session_Key_Encrypted)

#         # The data is decrypted using the AES "session key."
#         Cipher_AES = AES.new(Session_Key, AES.MODE_EAX, Nonce)
#         Plaintext = Cipher_AES.decrypt_and_verify(Ciphertext, Tag)
#         Plaintext = Plaintext.decode("utf-8")

#         OutputText_RSA.delete(1.0, "end")
#         OutputText_RSA.insert(1.0, Plaintext)
#         OutputText_RSA.bind("<Key>", lambda a: "break")
#     # except ValueError:
#         # Interface.messagebox.showerror("Error", "• Incorrect corresponding public or private key.")
#     # except TypeError:
#         # Interface.messagebox.showerror("Error", "• Invalid input data.")

Shell_Reset()