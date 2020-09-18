import os
import time
import random
import string
import base64

# It is preferred and likely necessary that you use Python 3.8+ if you are building this program.

try:
    # Python2
    import Tkinter as Interface
except ImportError:
    # Python3
    import tkinter as Interface

from tkinter import ttk as InterfaceExtension
from tkinter import messagebox
from tkinter import filedialog
from tkinter import *

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA256, SHA512, SHA3_256, SHA3_512
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

# Special widget tooltip class written by Stack Overflow users: crxguy52, Stevoisiak, Victor Zaccardo, 25mar16.
class CreateToolTip(object):
    # Create a tooltip for a given widget.
    def __init__(self, widget, text='widget info'):
        self.waittime = 500     # Milliseconds
        self.wraplength = 180   # Pixels
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.widget.bind("<ButtonPress>", self.leave)
        self.id = None
        self.tw = None

    def enter(self, event=None):
        self.schedule()

    def leave(self, event=None):
        self.unschedule()
        self.hidetip()

    def schedule(self):
        self.unschedule()
        self.id = self.widget.after(self.waittime, self.showtip)

    def unschedule(self):
        id = self.id
        self.id = None
        if id:
            self.widget.after_cancel(id)

    def showtip(self, event=None):
        x = y = 0
        x, y, cx, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        # Creates a toplevel window.
        self.tw = Interface.Toplevel(self.widget)
        # Leaves only the label and removes the app window.
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry("+%d+%d" % (x, y))
        label = Interface.Label(self.tw, text=self.text, justify='left',
                       background="#ffffff", relief='solid', borderwidth=1,
                       wraplength = self.wraplength)
        label.pack(ipadx=1)

    def hidetip(self):
        tw = self.tw
        self.tw= None
        if tw:
            tw.destroy()
#

def ProgramInfo():
    Interface.messagebox.showinfo("About", "This program primarily uses the following libraries to accomplish its functionality: tkinter, pycryptodome.\n\n\
If you're confused on how to properly use this tool, see the guide below.\n\n\
Symmetric Encryption:\n\
1. Enter your plaintext input data.\n\n\
2. Enter your encryption/decryption key (AES is a symmetric encryption algorithm, so the same key is used for both the encryption and decryption of data).\n\n\
3. The 'Password' input length no longer matters, as a secure key is derived from the input password during the encryption process.\n\n\
4. Click on 'Encrypt,' and your data will be encrypted using the given key, and a randomly generated initialization vector (IV). You will need to decrypt your \
data using the IV generated upon encryption, as this is the 'seed' that randomizes the ciphertext digest.\n\n\
5. Your ciphertext (encrypted data) will be output accordingly. To decrypt your data, just input the ciphertext in the 'Input' field, along with the key and your \
cipher's unique IV, and click 'Decrypt.'\n\n\
Asymmetric Encryption:\n\
1. Generate your public and private key pair with the given length (either 1024, 2048, or 4096).\n\n\
2. Use your public and private keys to sign, encrypt, or decrypt data.")

def Encrypt_AES():
    Plaintext = InputText.get("1.0", "end").rstrip()
    Plaintext_Byte = Plaintext.encode()
    Plaintext_Byte_Pad = pad(Plaintext_Byte, AES.block_size)
    # The encoded input data is padded to fit the AES block size (16-Byte).

    OutputProgress["value"] = 25
    Root.update_idletasks()
    time.sleep(0.05)

    # ------------------------------------------------------
    # KDF:
    if SelectedAlgorithm.get() == "AES-128":
        KeyLength = 16
    elif SelectedAlgorithm.get() == "AES-192":
        KeyLength = 24
    elif SelectedAlgorithm.get() == "AES-256":
        KeyLength = 32

    OutputProgress["value"] = 50
    Root.update_idletasks()
    time.sleep(0.05)

    Password = PasswordEntry.get().rstrip()
    Password_Encode = Password.encode()
    Salt = get_random_bytes(16)
    Key = scrypt(Password, Salt, KeyLength, N=2**20, r=8, p=1)
    # - ( 2¹⁴, 8, 1 ) for interactive logins (≤100ms)
    # - ( 2²⁰, 8, 1 ) for file encryption (≤5s)
    # ------------------------------------------------------

    # IV: An "initialization vector" is a 16-Byte randomly generated string that randomizes the digest for ciphertext generation, similar to a seed.
    # 16-Byte Key (128-bit)
    # 24-Byte Key (192-bit)
    # 32-Byte Key (256-bit)

    OutputProgress["value"] = 75
    Root.update_idletasks()
    time.sleep(0.05)

    Cipher = AES.new(Key, AES.MODE_CBC)

    Ciphertext = Cipher.encrypt(Plaintext_Byte_Pad)

    SaltEntry.delete(0, "end")
    SaltEntry.insert(0, base64.encodebytes(Salt))

    VectorEntry.delete(0, "end")
    VectorEntry.insert(0, base64.encodebytes(Cipher.iv))

    OutputText.delete(1.0, "end")
    OutputText.insert(1.0, base64.encodebytes(Ciphertext))
    OutputText.bind("<Key>", lambda a: "break")

    OutputProgress["value"] = 100
    Root.update_idletasks()
    time.sleep(0.05)

    OutputProgress["value"] = 0
    Root.update_idletasks()

def Decrypt_AES():
    try:
        Ciphertext = base64.b64decode(InputText.get("1.0", "end"))
        Salt = base64.b64decode(SaltEntry.get())
        Vector = base64.b64decode(VectorEntry.get())

        OutputProgress["value"] = 25
        Root.update_idletasks()
        time.sleep(0.05)

        # ------------------------------------------------------
        # Reverse KDF:
        if SelectedAlgorithm.get() == "AES-128":
            KeyLength = 16
        elif SelectedAlgorithm.get() == "AES-192":
            KeyLength = 24
        elif SelectedAlgorithm.get() == "AES-256":
            KeyLength = 32
        
        OutputProgress["value"] = 50
        Root.update_idletasks()
        time.sleep(0.05)

        Password = PasswordEntry.get()
        Password_Encode = Password.encode()
        Key = scrypt(Password, Salt, KeyLength, N=2**20, r=8, p=1)
        # ------------------------------------------------------

        OutputProgress["value"] = 75
        Root.update_idletasks()
        time.sleep(0.05)

        Cipher = AES.new(Key, AES.MODE_CBC, Vector)

        Plaintext = Cipher.decrypt(Ciphertext)
        Plaintext = unpad(Plaintext, AES.block_size)

        OutputText.delete(1.0, "end")
        OutputText.insert(1.0, Plaintext.decode())
        OutputText.bind("<Key>", lambda a: "break")

        OutputProgress["value"] = 100
        Root.update_idletasks()
        time.sleep(0.05)

        OutputProgress["value"] = 0
        Root.update_idletasks()
    except ValueError:
        Interface.messagebox.showerror("Error", "• Incorrect decryption key.")
        OutputProgress["value"] = 0
        Root.update_idletasks()

def Hash_Function():
    if SelectedHashFunction.get() == "SHA-256":
        Hash = SHA256.new()
    elif SelectedHashFunction.get() == "SHA-512":
        Hash = SHA512.new()
    elif SelectedHashFunction.get() == "SHA3-256":
        Hash = SHA3_256.new()
    elif SelectedHashFunction.get() == "SHA3-512":
        Hash = SHA3_512.new()
    
    Password_String = PasswordEntry.get()
    Hash.update(Password_String.encode())
    Password_Digest = str(Hash.hexdigest())
    PasswordEntry.delete(0, "end")
    PasswordEntry.insert(0, Password_Digest)

def KeyGeneration():
    ValueLength = int(SelectedRSALength.get())
    Key = RSA.generate(ValueLength)
    PrivateKey = Key.export_key()
    KeyOutput_Private.delete(1.0, "end")
    KeyOutput_Private.insert(1.0, PrivateKey)

    PublicKey = Key.publickey().export_key()
    KeyOutput_Public.delete(1.0, "end")
    KeyOutput_Public.insert(1.0, PublicKey)

def String():
    ValueLength = int(LengthEntry.get())
    RandomString = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(ValueLength))
    OutputText.delete(1.0, "end")
    OutputText.insert(1.0, RandomString)
    OutputText.bind("<Key>", lambda a: "break")

def Bytes():
    ValueLength = int(LengthEntry.get())
    RandomBytes = os.urandom(ValueLength)
    OutputText.delete(1.0, "end")
    OutputText.insert(1.0, str(RandomBytes))
    OutputText.bind("<Key>", lambda a: "break")

def Copy():
    Data = OutputText.get("1.0", "end")
    Data = Data[:-1]
    Root.clipboard_clear()
    Root.clipboard_append(Data)
    Root.update()

# Global Variable
KeyVisible = True

def Show():
    global KeyVisible
    if KeyVisible == True:
        PasswordEntry.configure(show="")
        ShowButton.configure(text="Hide")
        KeyVisible = False
        # return

    elif KeyVisible == False:
        PasswordEntry.configure(show="•")
        ShowButton.configure(text="Show")
        KeyVisible = True

def OpenData_AES():
    try:
        DataFile = filedialog.askopenfilename(initialdir="Documents", title="Load input data from a file...", filetypes=(("Vortex Cipher File", "*.vtxc"), ("Vortex Key File", "*.vtxk"), ("Text File", "*.txt"), ("All Files", "*.*")))
        Vortex_Extension = ".vtxc"
        if DataFile.endswith(Vortex_Extension):
            with open(DataFile, "r") as OpenFile:
                Salt = OpenFile.readline()
                IV = OpenFile.readline()
                Ciphertext = OpenFile.readlines()
                Index = ""

                for Data in Ciphertext:
                    Index = Index + Data
                    InputText.delete(1.0, "end")
                    InputText.insert(1.0, Index)

                SaltEntry.delete(0, "end")
                SaltEntry.insert(0, Salt)
                VectorEntry.delete(0, "end")
                VectorEntry.insert(0, IV)

                OpenFile.close()
        else:
            with open(DataFile, "r") as OpenFile:
                FileData = OpenFile.readlines()
                Index = ""
                for Data in FileData:
                    Index = Index + Data

                    InputText.delete(1.0, "end")
                    InputText.insert(1.0, Index)

                OpenFile.close()
    except FileNotFoundError:
        Interface.messagebox.showerror("Error", "• Invalid file or directory.")

def SaveData_AES():
    try:
        DataFile = filedialog.asksaveasfilename(initialdir="Documents", title="Save the output data to a file...", defaultextension=".vtxc", filetypes=(("Vortex Cipher File", "*.vtxc"), ("Text File", "*.txt"), ("All Files", "*.*")))
        Vortex_Extension = ".vtxc"
        if DataFile.endswith(Vortex_Extension):
            with open(DataFile, "w") as OpenFile:
                Salt = SaltEntry.get().rstrip()
                IV = VectorEntry.get().rstrip()
                Ciphertext = OutputText.get("1.0", "end").rstrip()

                OpenFile.writelines(Salt + "\n")
                OpenFile.writelines(IV + "\n")
                OpenFile.writelines(Ciphertext)

                OpenFile.close()
        else:
            with open(DataFile, "w") as OpenFile:
                Ciphertext = OutputText.get("1.0", "end").rstrip()

                OpenFile.writelines(Ciphertext)

                OpenFile.close()
    except FileNotFoundError:
        Interface.messagebox.showerror("Error", "• Invalid file or directory.")

def SaveData_RSA_Private():
    try:
        DataFile = filedialog.asksaveasfilename(initialdir="Documents", title="Save the private key to a file...", defaultextension=".vtxk", filetypes=(("Vortex Key File", "*.vtxk"), ("All Files", "*.*")))
        with open(DataFile, "w") as OpenFile:
            Private_Key = KeyOutput_Private.get("1.0", "end").rstrip()
            OpenFile.writelines(Private_Key)

            OpenFile.close()
    except FileNotFoundError:
        Interface.messagebox.showerror("Error", "• Invalid file or directory.")

def SaveData_RSA_Public():
    try:
        DataFile = filedialog.asksaveasfilename(initialdir="Documents", title="Save the public key to a file...", defaultextension=".vtxk", filetypes=(("Vortex Key File", "*.vtxk"), ("All Files", "*.*")))
        with open(DataFile, "w") as OpenFile:
            Public_Key = KeyOutput_Public.get("1.0", "end").rstrip()
            OpenFile.writelines(Public_Key)

            OpenFile.close()
    except FileNotFoundError:
        Interface.messagebox.showerror("Error", "• Invalid file or directory.")

def ThemeConfigure(BGColor, TextColor, FieldColor):
    Root.configure(bg=BGColor)
    LeftContainer.configure(bg=BGColor, fg=TextColor)
    RightContainer.configure(bg=BGColor, fg=TextColor)
    # - Left Container
    HeaderFrame_L.configure(bg=BGColor, fg=TextColor)
    ButtonFrameA.configure(bg=BGColor, fg=TextColor)
    ButtonFrameB.configure(bg=BGColor, fg=TextColor)
    BottomFrame.configure(bg=BGColor, fg=TextColor)
    ExtraFrameA.configure(bg=BGColor, fg=TextColor)
    ExtraFrameB.configure(bg=BGColor, fg=TextColor)
    FooterFrameA_L.configure(bg=BGColor, fg=TextColor)
    FooterFrameB_L.configure(bg=BGColor, fg=TextColor)
    ThemeLabel.configure(bg=BGColor, fg=TextColor)
    InputLabel.configure(bg=BGColor, fg=TextColor)
    OutputLabel.configure(bg=BGColor, fg=TextColor)
    LengthLabel.configure(bg=BGColor, fg=TextColor)
    PasswordLabel.configure(bg=BGColor, fg=TextColor)
    SaltLabel.configure(bg=BGColor, fg=TextColor)
    VectorLabel.configure(bg=BGColor, fg=TextColor)
    InputText.configure(bg=FieldColor, fg=TextColor, insertbackground=TextColor)
    PasswordEntry.configure(bg=FieldColor, fg=TextColor, insertbackground=TextColor)
    SaltEntry.configure(bg=FieldColor, fg=TextColor, insertbackground=TextColor)
    VectorEntry.configure(bg=FieldColor, fg=TextColor, insertbackground=TextColor)
    OutputText.configure(bg=FieldColor, fg=TextColor, insertbackground=TextColor)
    LengthEntry.configure(bg=FieldColor, fg=TextColor, insertbackground=TextColor)
    BGEntry.configure(bg=FieldColor, fg=TextColor, insertbackground=TextColor)
    FGEntry.configure(bg=FieldColor, fg=TextColor, insertbackground=TextColor)
    FieldEntry.configure(bg=FieldColor, fg=TextColor, insertbackground=TextColor)
    EncryptButton_AES.configure(bg=FieldColor, fg=TextColor)
    DecryptButton_AES.configure(bg=FieldColor, fg=TextColor)
    AlgorithmMenu.configure(bg=FieldColor, fg=TextColor)
    ShowButton.configure(bg=FieldColor, fg=TextColor)
    ExitButton.configure(bg=FieldColor, fg=TextColor)
    HashFunctionMenu.configure(bg=FieldColor, fg=TextColor)
    HashButton.configure(bg=FieldColor, fg=TextColor)
    OpenButton.configure(bg=FieldColor, fg=TextColor)
    SaveButton.configure(bg=FieldColor, fg=TextColor)
    SaveButton_Private.configure(bg=FieldColor, fg=TextColor)
    SaveButton_Public.configure(bg=FieldColor, fg=TextColor)
    StringButton.configure(bg=FieldColor, fg=TextColor)
    BytesButton.configure(bg=FieldColor, fg=TextColor)
    CopyButton.configure(bg=FieldColor, fg=TextColor)
    AboutButton.configure(bg=FieldColor, fg=TextColor)
    # - Right Container
    HeaderFrame_R.configure(bg=BGColor, fg=TextColor)
    OptionFrame_R.configure(bg=BGColor, fg=TextColor)
    KeyOutput_Private_Frame.configure(bg=BGColor, fg=TextColor)
    KeyOutput_Public_Frame.configure(bg=BGColor, fg=TextColor)
    RC_Label.configure(bg=BGColor, fg=TextColor)
    PrivateKeyLabel.configure(bg=BGColor, fg=TextColor)
    PublicKeyLabel.configure(bg=BGColor, fg=TextColor)
    RSALengthMenu.configure(bg=FieldColor, fg=TextColor)
    KeyOutput_Private.configure(bg=FieldColor, fg=TextColor, insertbackground=TextColor)
    KeyOutput_Public.configure(bg=FieldColor, fg=TextColor, insertbackground=TextColor)
    GenerateButton.configure(bg=FieldColor, fg=TextColor)

def InitialTheme_Read():
    try:
        with open("Theme.ini", "r") as ThemeFile:
            Theme = ThemeFile.readline().rstrip()
            BGColor = ThemeFile.readline().rstrip()
            TextColor = ThemeFile.readline().rstrip()
            FieldColor = ThemeFile.readline().rstrip()

            ThemeConfigure(BGColor=BGColor, TextColor=TextColor, FieldColor=FieldColor)
            ThemeList.set(Theme)
            BGEntry.delete(0, "end")
            BGEntry.insert(0, BGColor)
            FGEntry.delete(0, "end")
            FGEntry.insert(0, TextColor)
            FieldEntry.delete(0, "end")
            FieldEntry.insert(0, FieldColor)

            ThemeFile.close()
    except FileNotFoundError:
        Interface.messagebox.showerror("Error", "• Initial theme configuration file 'Theme.ini' not found.")

def InitialTheme_Write():
    try:
        with open("Theme.ini", "w") as ThemeFile:
            Theme = ThemeList.get().rstrip()
            BGColor = BGEntry.get().rstrip()
            TextColor = FGEntry.get().rstrip()
            FieldColor = FieldEntry.get().rstrip()

            ThemeFile.writelines(Theme + "\n")
            ThemeFile.writelines(BGColor + "\n")
            ThemeFile.writelines(TextColor + "\n")
            ThemeFile.writelines(FieldColor)

            ThemeFile.close()
    except FileNotFoundError:
        Interface.messagebox.showerror("Error", "• Initial theme configuration 'Theme.ini' file not found.")

def ThemeChanged(event):
    if ThemeList.get() == "Vortex":
        BGColor = "#000000" # Black
        TextColor = "#00ffff" # Cyan
        FieldColor = "#000000" # Black
        
        BGEntry.delete(0, "end")
        BGEntry.insert(0, BGColor)
        FGEntry.delete(0, "end")
        FGEntry.insert(0, TextColor)
        FieldEntry.delete(0, "end")
        FieldEntry.insert(0, FieldColor)

        ThemeConfigure(BGColor=BGColor, TextColor=TextColor, FieldColor=FieldColor)

    elif ThemeList.get() == "Terminal":
        BGColor = "#000000" # Black
        TextColor = "#00ff00" # Lime
        FieldColor = "#000000" # Black
        
        BGEntry.delete(0, "end")
        BGEntry.insert(0, BGColor)
        FGEntry.delete(0, "end")
        FGEntry.insert(0, TextColor)
        FieldEntry.delete(0, "end")
        FieldEntry.insert(0, FieldColor)

        ThemeConfigure(BGColor=BGColor, TextColor=TextColor, FieldColor=FieldColor)
    
    elif ThemeList.get() == "Sinister":
        BGColor = "#060606" # Black
        TextColor = "#dd0000" # Red
        FieldColor = "#060606" # Black
        
        BGEntry.delete(0, "end")
        BGEntry.insert(0, BGColor)
        FGEntry.delete(0, "end")
        FGEntry.insert(0, TextColor)
        FieldEntry.delete(0, "end")
        FieldEntry.insert(0, FieldColor)

        ThemeConfigure(BGColor=BGColor, TextColor=TextColor, FieldColor=FieldColor)

    elif ThemeList.get() == "Halloween":
        BGColor = "#060606" # Black
        TextColor = "#ff9900" # Orange
        FieldColor = "#060606" # Black
        
        BGEntry.delete(0, "end")
        BGEntry.insert(0, BGColor)
        FGEntry.delete(0, "end")
        FGEntry.insert(0, TextColor)
        FieldEntry.delete(0, "end")
        FieldEntry.insert(0, FieldColor)

        ThemeConfigure(BGColor=BGColor, TextColor=TextColor, FieldColor=FieldColor)

    elif ThemeList.get() == "Solaris":
        BGColor = "#3c5d75" # Deep Blue
        TextColor = "#000000" # Black
        FieldColor = "#c5c5c5" # Light Gray
        
        BGEntry.delete(0, "end")
        BGEntry.insert(0, BGColor)
        FGEntry.delete(0, "end")
        FGEntry.insert(0, TextColor)
        FieldEntry.delete(0, "end")
        FieldEntry.insert(0, FieldColor)

        ThemeConfigure(BGColor=BGColor, TextColor=TextColor, FieldColor=FieldColor)

    elif ThemeList.get() == "Crimson":
        BGColor = "#250000" # Dark Red
        TextColor = "#eeeeee" # White (Darker)
        FieldColor = "#450000" # Dark Red
        
        BGEntry.delete(0, "end")
        BGEntry.insert(0, BGColor)
        FGEntry.delete(0, "end")
        FGEntry.insert(0, TextColor)
        FieldEntry.delete(0, "end")
        FieldEntry.insert(0, FieldColor)

        ThemeConfigure(BGColor=BGColor, TextColor=TextColor, FieldColor=FieldColor)

    elif ThemeList.get() == "Sky":
        BGColor = "#111111" # Dark Gray
        TextColor = "#add8e6" # Light Blue
        FieldColor = "#111111" # Dark Gray
        
        BGEntry.delete(0, "end")
        BGEntry.insert(0, BGColor)
        FGEntry.delete(0, "end")
        FGEntry.insert(0, TextColor)
        FieldEntry.delete(0, "end")
        FieldEntry.insert(0, FieldColor)

        ThemeConfigure(BGColor=BGColor, TextColor=TextColor, FieldColor=FieldColor)

    elif ThemeList.get() == "Light":
        BGColor = "#c5c5c5" # Light Gray
        TextColor = "#000000" # Black
        FieldColor = "#eeeeee" # White (Darker)
        
        BGEntry.delete(0, "end")
        BGEntry.insert(0, BGColor)
        FGEntry.delete(0, "end")
        FGEntry.insert(0, TextColor)
        FieldEntry.delete(0, "end")
        FieldEntry.insert(0, FieldColor)

        ThemeConfigure(BGColor=BGColor, TextColor=TextColor, FieldColor=FieldColor)

    elif ThemeList.get() == "Dark":
        BGColor = "#111111" # Dark Gray
        TextColor = "#dddddd" # White (Darker)
        FieldColor = "#000000" # Black
        
        BGEntry.delete(0, "end")
        BGEntry.insert(0, BGColor)
        FGEntry.delete(0, "end")
        FGEntry.insert(0, TextColor)
        FieldEntry.delete(0, "end")
        FieldEntry.insert(0, FieldColor)

        ThemeConfigure(BGColor=BGColor, TextColor=TextColor, FieldColor=FieldColor)

    elif ThemeList.get() == "Custom":
        BGColor = BGEntry.get()
        TextColor = FGEntry.get()
        FieldColor = FieldEntry.get()

        ThemeConfigure(BGColor=BGColor, TextColor=TextColor, FieldColor=FieldColor)
    
    InitialTheme_Write()

# - Section A (Root, Frame)

Root = Interface.Tk()
Root.title("Vortex (VTX) Crypto VID: 1.1.0, Author: WorldDstroyer")
Root.iconbitmap("Vortex-Icon.ico")
Root.configure(bg="black")
Root.resizable(False, False)

# - Left Half (Frame)
LeftContainer = LabelFrame(Root, bd=5, bg="black", fg="cyan", text="Symmetric Key Encryption (AES)", width=200, height=275)
LeftContainer.pack(padx=5, pady=5, side="left", anchor="w")

HeaderFrame_L = LabelFrame(LeftContainer, bd=0, bg="black", fg="cyan", width=200, height=275)
HeaderFrame_L.pack(padx=5)

ButtonFrameA = LabelFrame(LeftContainer, bd=0, bg="black", fg="cyan", width=250, height=25)
ButtonFrameA.pack(padx=5, pady=5)

ButtonFrameB = LabelFrame(LeftContainer, bd=0, bg="black", fg="cyan", width=250, height=25)
ButtonFrameB.pack(padx=5, pady=5)

BottomFrame = LabelFrame(LeftContainer, bd=0, bg="black", fg="cyan", width=250, height=25)
BottomFrame.pack(padx=5, pady=5)

ExtraFrameA = LabelFrame(LeftContainer, bd=0, bg="black", fg="cyan", width=250, height=25)
ExtraFrameA.pack(padx=5)

ExtraFrameB = LabelFrame(LeftContainer, bd=0, bg="black", fg="cyan", width=250, height=25)
ExtraFrameB.pack(padx=5, pady=5)

FooterFrameA_L = LabelFrame(LeftContainer, bd=0, bg="black", fg="cyan", text="Theme Configuration (Order: BG, FG/Text, Button/Field)", width=250, height=25)
FooterFrameA_L.pack(padx=5, pady=5)

FooterFrameB_L = LabelFrame(LeftContainer, bd=0, bg="black", fg="cyan", width=250, height=25)
FooterFrameB_L.pack()

# - Right Half (Frame)
RightContainer = LabelFrame(Root, bd=5, bg="black", fg="cyan", text="Public Key Encryption (RSA)", width=200, height=275)
RightContainer.pack(padx=5, side="right", anchor="e")

HeaderFrame_R = LabelFrame(RightContainer, bd=0, bg="black", fg="cyan", width=200, height=275)
HeaderFrame_R.pack(padx=10)

OptionFrame_R = LabelFrame(RightContainer, bd=0, bg="black", fg="cyan", width=200, height=275)
OptionFrame_R.pack(padx=10)

KeyOutput_Private_Frame = LabelFrame(RightContainer, bd=0, bg="black", fg="cyan", width=200, height=275)
KeyOutput_Private_Frame.pack(padx=10)

KeyOutput_Public_Frame = LabelFrame(RightContainer, bd=0, bg="black", fg="cyan", width=200, height=275)
KeyOutput_Public_Frame.pack(padx=10)

FooterFrame_R = LabelFrame(RightContainer, bd=0, bg="black", fg="cyan", width=200, height=275)
FooterFrame_R.pack(padx=10, pady=5)

# --------------------------------------------------------------------------------------------------------------------
# - Program Left Half -
# --------------------------------------------------------------------------------------------------------------------

# - Section B (Label)

ThemeLabel = Interface.Label(FooterFrameA_L, bg="black", fg="cyan", font="Arial 12 bold", text="Theme:")
ThemeLabel.pack(side="left", fill=None, expand=False, anchor="w")

# Theme Dropdown
ThemeOptions = [
    "Vortex",
    "Terminal",
    "Sinister",
    "Halloween",
    "Solaris",
    "Crimson",
    "Sky",
    "Light",
    "Dark",
    "Custom",
]

Theme = StringVar()
Theme.set("Vortex")
ThemeList = InterfaceExtension.Combobox(FooterFrameA_L, value=ThemeOptions)
ThemeList.current(0)
ThemeList.bind("<<ComboboxSelected>>", ThemeChanged)
ThemeList.configure(font="Arial 12 bold", width=9)
ThemeList.pack(side="left", fill=None, expand=False, anchor="w")

InputLabel = Interface.Label(HeaderFrame_L, bg="black", fg="cyan", font="Arial 12 bold", text="Input Data:")
InputLabel.pack(side="top", fill=None, expand=False, anchor="n")

OutputLabel = Interface.Label(BottomFrame, bg="black", fg="cyan", font="Arial 12 bold", text="Output Data:")
OutputLabel.pack(side="top", fill=None, expand=False, anchor="n")

LengthLabel = Interface.Label(ExtraFrameA, bg="black", fg="cyan", font="Arial 12 bold", text="Length:")
LengthLabel.pack(side="top", fill=None, expand=False, anchor="n")

# - Section C (Text, Entry)

VectorEntry = Interface.Entry(HeaderFrame_L, width=45)
VectorEntry.configure(bg="black", fg="cyan", insertbackground="cyan", font="Arial 12 bold")
VectorEntry.pack(pady=5, side="bottom", fill=None, expand=False, anchor="s")

# # # # #
VectorLabel = Interface.Label(HeaderFrame_L, bg="black", fg="cyan", font="Arial 12 bold", text="Initialization Vector (Cipher):")
VectorLabel.pack(side="bottom", fill=None, expand=False, anchor="s")
# # # # #

SaltEntry = Interface.Entry(HeaderFrame_L, width=45)
SaltEntry.configure(bg="black", fg="cyan", insertbackground="cyan", font="Arial 12 bold")
SaltEntry.pack(pady=5, side="bottom", fill=None, expand=False, anchor="s")

# # # # #
SaltLabel = Interface.Label(HeaderFrame_L, bg="black", fg="cyan", font="Arial 12 bold", text="Salt (Key):")
SaltLabel.pack(side="bottom", fill=None, expand=False, anchor="s")
# # # # #

InputText = Interface.Text(HeaderFrame_L, bg="black", fg="cyan", insertbackground="cyan", font="Arial 12 bold", wrap=WORD, width=45, height=10)
InputText.pack(pady=5, side="top", fill=None, expand=False, anchor="n")

PasswordEntry = Interface.Entry(HeaderFrame_L, width=45)
PasswordEntry.configure(bg="black", fg="cyan", insertbackground="cyan", font="Arial 12 bold", show="•")
PasswordEntry.pack(pady=5, side="bottom", fill=None, expand=False, anchor="s")

# # # # #
PasswordLabel = Interface.Label(HeaderFrame_L, bg="black", fg="cyan", font="Arial 12 bold", text="Password:")
PasswordLabel.pack(side="bottom", fill=None, expand=False, anchor="s")
# # # # #

OutputProgress = InterfaceExtension.Progressbar(BottomFrame, orient=HORIZONTAL, length=408.5, mode="determinate")
OutputProgress.pack(side="bottom", fill=None, expand=False, anchor="s")

OutputText = Interface.Text(BottomFrame, bg="black", fg="cyan", insertbackground="cyan", font="Arial 12 bold", wrap=WORD, width=45, height=10)
OutputText.pack(pady=5, side="bottom", fill=None, expand=False, anchor="s")

LengthEntry = Interface.Entry(ExtraFrameA, bg="black", fg="cyan", insertbackground="cyan", font="Arial 12 bold", justify="center", width=8)
LengthEntry.pack(side="top", fill=None, expand=False, anchor="n")

BGEntry = Interface.Entry(FooterFrameA_L, bg="black", fg="cyan", insertbackground="cyan", font="Arial 12 bold", justify="center", width=9)
BGEntry.pack(side="left", fill=None, expand=False, anchor="w")

FGEntry = Interface.Entry(FooterFrameA_L, bg="black", fg="cyan", insertbackground="cyan", font="Arial 12 bold", justify="center", width=9)
FGEntry.pack(side="left", fill=None, expand=False, anchor="w")

FieldEntry = Interface.Entry(FooterFrameA_L, bg="black", fg="cyan", insertbackground="cyan", font="Arial 12 bold", justify="center", width=9)
FieldEntry.pack(side="left", fill=None, expand=False, anchor="w")

# - Section D (Button)

# "Encrypt" Button
EncryptButton_AES = Interface.Button(ButtonFrameA, bg="black", fg="cyan", font="Arial 12 bold", text="Encrypt", command=Encrypt_AES)
EncryptButton_AES.pack(side="left", fill=None, expand=False, anchor="w")
#

# "Decrypt" Button
DecryptButton_AES = Interface.Button(ButtonFrameA, bg="black", fg="cyan", font="Arial 12 bold", text="Decrypt", command=Decrypt_AES)
DecryptButton_AES.pack(side="left", fill=None, expand=False, anchor="w")
#

# Algorithm Dropdown
SelectedAlgorithm = StringVar()
SelectedAlgorithm.set("AES-256")
AlgorithmList = [
    "AES-128",
    "AES-192",
    "AES-256",
]
AlgorithmMenu = Interface.OptionMenu(ButtonFrameA, SelectedAlgorithm, *AlgorithmList, command=Root.update())
AlgorithmMenu.configure(bg="black", fg="cyan", font="Arial 12 bold")
AlgorithmMenu.pack(side="left", fill=None, expand=False, anchor="w")
#

# "Show/Hide" Button
ShowButton = Interface.Button(ButtonFrameA, command=Show)
ShowButton.configure(bg="black", fg="cyan", font="Arial 12 bold", text="Show")
ShowButton.pack(side="left", fill=None, expand=False, anchor="w")
#

# "Exit" Button
ExitButton = Interface.Button(ButtonFrameA, bg="black", fg="cyan", font="Arial 12 bold", text="Exit", command=Root.quit)
ExitButton.pack(side="left", fill=None, expand=False, anchor="w")
#

# Hash Function Dropdown
SelectedHashFunction = StringVar()
SelectedHashFunction.set("SHA-512")
HashFunctionList = [
    "SHA-256",
    "SHA-512",
    "SHA3-256",
    "SHA3-512",
]
HashFunctionMenu = Interface.OptionMenu(ButtonFrameB, SelectedHashFunction, *HashFunctionList, command=Root.update())
HashFunctionMenu.configure(bg="black", fg="cyan", font="Arial 12 bold")
HashFunctionMenu.pack(side="left", fill=None, expand=False, anchor="w")
#

# "Hash Password (*)" Button
HashButton = Interface.Button(ButtonFrameB, bg="black", fg="cyan", font="Arial 12 bold", text="Hash Password (*)", command=Hash_Function)
HashButton.pack(side="left", fill=None, expand=False, anchor="w")
HashButton_TTP = CreateToolTip(HashButton, text="This is not necessary, as the key is derived securely from the password in the encryption process.")
#

# "Open" Button
OpenButton = Interface.Button(ButtonFrameB, bg="black", fg="cyan", font="Arial 12 bold", text="Open", command=OpenData_AES)
OpenButton.pack(side="left", fill=None, expand=False, anchor="w")
#

# "Save" Button
SaveButton = Interface.Button(ButtonFrameB, bg="black", fg="cyan", font="Arial 12 bold", text="Save", command=SaveData_AES)
SaveButton.pack(side="left", fill=None, expand=False, anchor="w")
#

# "Random String" Button
StringButton = Interface.Button(ExtraFrameB, bg="black", fg="cyan", font="Arial 12 bold", text="Random String", command=String)
StringButton.pack(side="left", fill=None, expand=False, anchor="w")
#

# "Random Bytes" Button
BytesButton = Interface.Button(ExtraFrameB, bg="black", fg="cyan", font="Arial 12 bold", text="Random Bytes", command=Bytes)
BytesButton.pack(side="left", fill=None, expand=False, anchor="w")
#

# "Copy Output" Button
CopyButton = Interface.Button(ExtraFrameB, bg="black", fg="cyan", font="Arial 12 bold", text="Copy Output", command=Copy)
CopyButton.pack(side="left", fill=None, expand=False, anchor="w")
#

# "About | Help" Button
AboutButton = Interface.Button(FooterFrameB_L, bg="black", fg="cyan", font="Arial 12 bold", text="About | Help", command=ProgramInfo)
AboutButton.pack(side="bottom", fill=None, expand=False, anchor="s")
#

# --------------------------------------------------------------------------------------------------------------------
# - Program Right Half -
# --------------------------------------------------------------------------------------------------------------------

# - Section A (Label)

RC_Label = Interface.Label(HeaderFrame_R, bg="black", fg="cyan", font="Arial 12 bold", text="Private | Public Key Generation:")
RC_Label.pack(side="top", fill=None, expand=False, anchor="n")

PrivateKeyLabel = Interface.Label(KeyOutput_Private_Frame, bg="black", fg="cyan", font="Arial 12 bold", text="Private Key:")
PrivateKeyLabel.pack(side="top", fill=None, expand=False, anchor="n")

PublicKeyLabel = Interface.Label(KeyOutput_Public_Frame, bg="black", fg="cyan", font="Arial 12 bold", text="Public Key:")
PublicKeyLabel.pack(side="top", fill=None, expand=False, anchor="n")

# - Section B (Entry)

# "Generate" Button
GenerateButton = Interface.Button(OptionFrame_R, bg="black", fg="cyan", font="Arial 12 bold", text="Generate", command=KeyGeneration)
GenerateButton.pack(side="left", fill=None, expand=False, anchor="w")
#

# RSA Key Length Dropdown
SelectedRSALength = StringVar()
SelectedRSALength.set("2048")
RSALengthList = [
    "1024",
    "2048",
    "4096",
]
RSALengthMenu = Interface.OptionMenu(OptionFrame_R, SelectedRSALength, *RSALengthList, command=Root.update())
RSALengthMenu.configure(bg="black", fg="cyan", font="Arial 12 bold")
RSALengthMenu.pack(pady=5, side="left", fill=None, expand=False, anchor="w")
#

KeyOutput_Private = Interface.Text(KeyOutput_Private_Frame, bg="black", fg="cyan", insertbackground="cyan", font="Arial 12 bold", width=45, height=10)
KeyOutput_Private.pack(pady=5, side="top", fill=None, expand=False, anchor="n")

KeyOutput_Public = Interface.Text(KeyOutput_Public_Frame, bg="black", fg="cyan", insertbackground="cyan", font="Arial 12 bold", width=45, height=10)
KeyOutput_Public.pack(pady=5, side="top", fill=None, expand=False, anchor="n")

# - Section C (Button)

# "Save Private Key" Button
SaveButton_Private = Interface.Button(FooterFrame_R, bg="black", fg="cyan", font="Arial 12 bold", text="Save Private Key", command=SaveData_RSA_Private)
SaveButton_Private.pack(side="left", fill=None, expand=False, anchor="w")
#

# "Save Public Key" Button
SaveButton_Public = Interface.Button(FooterFrame_R, bg="black", fg="cyan", font="Arial 12 bold", text="Save Public Key", command=SaveData_RSA_Public)
SaveButton_Public.pack(side="left", fill=None, expand=False, anchor="w")
#

# --------------------------------------------------------------------------------------------------------------------
# - Runtime Functions -
# --------------------------------------------------------------------------------------------------------------------
InitialTheme_Read()
# --------------------------------------------------------------------------------------------------------------------

Interface.mainloop()