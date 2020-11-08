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
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import MD2, MD4, MD5, SHA1, SHA256, SHA512, SHA3_256, SHA3_512
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

# Terminal Color Definitions
RESET = '\033[0m'
# Formatting Codes (Windows Compatibility Concern)
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
| Date: 10-10-2020                                                                           |
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
2: AES
3: RSA
4: Hash
5: Random
6: Exit\
''' % (LIGHTGREEN, THEMECOLOR)
    print(VOD + LIGHTYELLOW)
    Option = input("")

    if Option == "1": F_Theme_Configure()
    elif Option == "2": F_AES()
    elif Option == "3": F_RSA()
    elif Option == "4": F_Hash()
    elif Option == "5": F_Random()
    elif Option == "6":
        print(THEMECOLOR + "Exiting program...")
        time.sleep(1.0)
        colorama.deinit()
        return

    elif Option == "cls":
        subprocess.call('cls',shell=True)
        global Program_Header
        print(Program_Header)
        F_Main()

    elif Option == "ls":
        print(THEMECOLOR)
        Path = input("Path: ")
        print("")
        try:
            for File in os.listdir(Path):
                if File.endswith(".txt") or File.endswith(".vtxc") or File.endswith(".vsfp"):
                    print(LIGHTYELLOW + os.path.join(Path, File) + THEMECOLOR)
        except FileNotFoundError:
            print(LIGHTRED + "Error: No such file exists." + THEMECOLOR)
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
'''\

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

def F_AES():
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/F_AES                  |
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

    if Option_AES == "1": F_AES_Gate_File()
    elif Option_AES == "2": F_AES_Gate_String()
    elif Option_AES == "3":
        global AES_Help
        print(AES_Help)
        F_AES()

    elif Option_AES == "!": F_Main()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_AES()

def F_AES_Gate_File():
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

    if Option == "1": F_AES_Encrypt_File()
    elif Option == "2": F_AES_Decrypt_File()
    elif Option == "!": F_AES()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_AES()

def F_AES_Encrypt_File():
    pass

def F_AES_Decrypt_File():
    pass

def F_AES_Gate_String():
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
                F_AES_Gate_String()

        elif Option_Import == "n":
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
            F_AES()

        F_AES_Encrypt_String(plaintext=Plaintext, password=Password, key_size=Key_Size)

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
                F_AES_Gate_String()

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
            F_AES()

        F_AES_Decrypt_String(ciphertext = Ciphertext, iv = IV, password = str(Password), salt = Salt, key_size = Key_Size)

    # - Back
    elif Option == "!": F_AES()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_AES()

def F_AES_Encrypt_String(plaintext, password, key_size):
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
            F_AES_Gate_String()

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
            F_AES_Save_String(file_path=File_Export, salt=Base64_Salt.decode(), iv=Base64_IV.decode(), ciphertext=Base64_Ciphertext.decode())
            F_AES_Gate_String()

        elif Save_Option == "n": F_AES_Gate_String()
        else:
            print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
            time.sleep(1.0)
            F_AES_Gate_String()

def F_AES_Decrypt_String(ciphertext, iv, password, salt, key_size):
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
            F_AES_Gate_String()

        Key = scrypt(password, Salt, Key_Length, N=2**20, r=8, p=1)
        # ------------------------------------------------------ #

        Cipher = AES.new(Key, AES.MODE_CBC, IV)

        Plaintext = Cipher.decrypt(Ciphertext)
        Plaintext = unpad(Plaintext, AES.block_size)

        print(THEMECOLOR)
        print("- Output (Decrypt) -")
        print(LIGHTGREEN + "Plaintext:" + "\n" + LIGHTYELLOW + Plaintext.decode() + THEMECOLOR)
        F_AES_Gate_String()
    except ValueError:
        print(LIGHTRED + "Error: Incorrect password." + THEMECOLOR)
        time.sleep(1.0)
        F_AES_Gate_String()

def F_AES_Save_String(file_path, salt, iv, ciphertext):
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

def F_RSA():
    Function_Header = THEMECOLOR + '''
------------------------------------------
| - Vortex-Crypto/F_RSA                  |
------------------------------------------'''
    print(Function_Header)
    Option = input("")

    F_Main()

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

            if Option_Function == "1": Function = MD2.new()
            elif Option_Function == "2": Function = MD4.new()
            elif Option_Function == "3": Function = MD5.new()
            elif Option_Function == "4": Function = SHA1.new()
            elif Option_Function == "5": Function = SHA256.new()
            elif Option_Function == "6": Function = SHA512.new()
            elif Option_Function == "7": Function = SHA3_256.new()
            elif Option_Function == "8": Function = SHA3_512.new()

            Layers = int(input("Layers: "))
            F_Hash_Generate(data=Data, function=Function, layers=Layers)
        except ValueError:
            print(LIGHTRED + "Error: One or more invalid arguments." + THEMECOLOR)
            time.sleep(1.0)
            F_Hash()

    elif Option == "2":
        print(THEMECOLOR)
        print("- Create Rainbow Table -")
        F_Rainbow()

    elif Option == "!": F_Main()
    else:
        print(LIGHTRED + "Error: Response invalid." + THEMECOLOR)
        time.sleep(1.0)
        F_Hash()

def F_Hash_Generate(data, function, layers):
    try:
        Hash_Label = str(function)[1:-20]
        Hash_Label = Hash_Label.replace("Crypto.Hash.", "")
        Hash_Label = Hash_Label.replace("object at", "")
        Hash_Label = Hash_Label.rstrip()

        Process_Begin = time.time()

        # - Note to self: try a nested for loop.
        for i in range(layers):
            Hash = function.new(data=data.encode())
            Digest = str(function.hexdigest())
            data = Digest

        print(LIGHTGREEN + "Hash Function: %s | Layers: %d | Digest:" % (Hash_Label, layers) + "\n" + LIGHTYELLOW + Digest + THEMECOLOR)

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
    elif Option == "!": F_Main()
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
        print("- Random String (Letters) -")
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
        F_Random_Choice_Default(file = File, count = int(Count), mode = 1)

    elif Option == "2": # Secure
        print(THEMECOLOR)
        File = input("File: ")
        Count = input("Count: ")
        F_Random_Choice_Secure(file = File, count = int(Count), mode = 2)

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
                print(LIGHTGREEN + "Choice:" + LIGHTYELLOW + Choice + THEMECOLOR)
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
                print(LIGHTGREEN + "Choice:" + LIGHTYELLOW + Choice + THEMECOLOR)
            F_Random()
        except FileNotFoundError:
            print(LIGHTRED + "Error: No such file exists." + THEMECOLOR)
            time.sleep(1.0)
            F_Random()

    F_Random()

# def F_RSA_Encrypt():
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

# def F_RSA_Decrypt():
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

F_Main()