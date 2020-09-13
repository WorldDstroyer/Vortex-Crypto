import os
import random
import string
import tkinter as Interface
from tkinter import ttk as InterfaceExtension
from tkinter import messagebox
from tkinter import filedialog
from tkinter import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

def ProgramInfo():
    Interface.messagebox.showinfo("About", "This program primarily uses the following libraries to accomplish its functionality: tkinter, pycryptodome.\n\n\
If you're confused on how to properly use this tool, see the guide below.\n\n\
1. Enter your plaintext input data.\n\n\
2. Enter your encryption/decryption key (AES is a symmetric encryption algorithm, so the same key is used for both the encryption and decryption of data).\n\n\
3. If the length of your key is not 16, 24, or 32 characters exactly, you can use the 'Hash | Trim Key (SHA-512)' button to hash your password in SHA-512, and \
automatically trim the key to the desired length. The length the password is trimmed to will depend on the AES mode you have currently selected \
(AES-128: 16, AES-192: 24, AES-256: 32).\n\n\
4. Click on 'Encrypt,' and your data will be encrypted using the given key, and a randomly generated initialization vector (IV). You will need to decrypt your \
data using the IV generated upon encryption, as this is the 'seed' that randomizes the ciphertext digest.\n\n\
5. Your ciphertext (encrypted data) will be output accordingly. To decrypt your data, just input the ciphertext in the 'Input' field, along with the key and your \
cipher's unique IV, and click 'Decrypt.'")

def Encrypt():
    Plaintext = InputText.get("1.0", "end").rstrip()
    EncodedPlaintext = Plaintext.encode()
    ConvertedPlaintext = pad(EncodedPlaintext, AES.block_size)
    # The encoded input data is padded to fit the AES block size (16-Byte).

    Key = KeyEntry.get()
    EncodedKey = Key.encode()
    # 16-Byte Key (128-bit)
    # 24-Byte Key (192-bit)
    # 32-Byte Key (256-bit)

    # IV: An "initialization vector" is a randomly generated string that randomizes the digest for ciphertext generation, similar to a seed.
    # Vector = os.urandom(16)

    Cipher = AES.new(EncodedKey, AES.MODE_CBC)

    Ciphertext = Cipher.encrypt(ConvertedPlaintext)

    VectorEntry.delete(0, "end")
    VectorEntry.insert(0, Cipher.iv)

    OutputText.delete(1.0, "end")
    OutputText.insert(1.0, Ciphertext)
    OutputText.bind("<Key>", lambda a: "break")

def Decrypt():
    Ciphertext = bytes(InputText.get("1.0", "end").rstrip(),"latin-1")
    Vector = bytes(VectorEntry.get(),"latin-1")
    Key = KeyEntry.get()
    EncodedKey = Key.encode()

    Cipher = AES.new(EncodedKey, AES.MODE_CBC, Vector)

    Plaintext = Cipher.decrypt(Ciphertext)
    Plaintext = unpad(Plaintext, AES.block_size)

    OutputText.delete(1.0, "end")
    OutputText.insert(1.0, Plaintext.decode())
    OutputText.bind("<Key>", lambda a: "break")

# Global Variable
TrimLength = 32

def KeyHash():
    global TrimLength

    if SelectedAlgorithm.get() == "AES-128":
        TrimLength = 16
    elif SelectedAlgorithm.get() == "AES-192":
        TrimLength = 24
    elif SelectedAlgorithm.get() == "AES-256":
        TrimLength = 32
    Key = KeyEntry.get()
    Hash = SHA512.new()
    Hash.update(Key.encode())
    KeyEntry.delete(0, "end")
    KeyEntry.insert(0, str(Hash.hexdigest()[:TrimLength]))

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
        KeyEntry.configure(show="")
        ShowButton.configure(text="Hide")
        KeyVisible = False
        # return

    elif KeyVisible == False:
        KeyEntry.configure(show="•")
        ShowButton.configure(text="Show")
        KeyVisible = True

def OpenData():
    DataFile = filedialog.askopenfilename(initialdir="Documents", title="Save File", filetypes=(("Vortex Cipher File", "*.vtxc"), ("All Files", "*.*")))
    with open(DataFile, "rb") as OpenFile:
        IV = OpenFile.read(16)
        Ciphertext = OpenFile.read()
    VectorEntry.delete(0, "end")
    VectorEntry.insert(0, IV)
    InputText.delete(1.0, "end")
    InputText.insert(1.0, Ciphertext)

def SaveData():
    DataFile = filedialog.asksaveasfilename(initialdir="Documents", title="Save File", defaultextension=".vtxc", filetypes=(("Vortex Cipher File", "*.vtxc"), ("All Files", "*.*")))
    print(DataFile)
    with open(DataFile, "wb") as OpenFile:
        IV = VectorEntry.get()
        IV = IV.encode("latin-1")
        Ciphertext = OutputText.get("1.0", "end")
        Ciphertext = Ciphertext.encode("latin-1")
        OpenFile.write(IV)
        OpenFile.write(Ciphertext)

def ThemeConfigure(BGColor, TextColor, FieldColor):
    Root.configure(bg=BGColor)
    HeaderFrame.configure(bg=BGColor, fg=TextColor)
    ButtonFrameA.configure(bg=BGColor, fg=TextColor)
    ButtonFrameB.configure(bg=BGColor, fg=TextColor)
    BottomFrame.configure(bg=BGColor, fg=TextColor)
    ExtraFrameA.configure(bg=BGColor, fg=TextColor)
    ExtraFrameB.configure(bg=BGColor, fg=TextColor)
    FooterFrameA.configure(bg=BGColor, fg=TextColor)
    FooterFrameB.configure(bg=BGColor, fg=TextColor)
    ThemeLabel.configure(bg=BGColor, fg=TextColor)
    InputLabel.configure(bg=BGColor, fg=TextColor)
    OutputLabel.configure(bg=BGColor, fg=TextColor)
    LengthLabel.configure(bg=BGColor, fg=TextColor)
    VectorLabel.configure(bg=BGColor, fg=TextColor)
    InputText.configure(bg=FieldColor, fg=TextColor)
    KeyEntry.configure(bg=FieldColor, fg=TextColor)
    KeyLabel.configure(bg=BGColor, fg=TextColor)
    VectorEntry.configure(bg=FieldColor, fg=TextColor)
    OutputText.configure(bg=FieldColor, fg=TextColor)
    LengthEntry.configure(bg=FieldColor, fg=TextColor)
    BGEntry.configure(bg=FieldColor, fg=TextColor)
    FGEntry.configure(bg=FieldColor, fg=TextColor)
    FieldEntry.configure(bg=FieldColor, fg=TextColor)
    EncryptButton.configure(bg=FieldColor, fg=TextColor)
    DecryptButton.configure(bg=FieldColor, fg=TextColor)
    AlgorithmMenu.configure(bg=FieldColor, fg=TextColor)
    ShowButton.configure(bg=FieldColor, fg=TextColor)
    ExitButton.configure(bg=FieldColor, fg=TextColor)
    HashButton.configure(bg=FieldColor, fg=TextColor)
    OpenButton.configure(bg=FieldColor, fg=TextColor)
    SaveButton.configure(bg=FieldColor, fg=TextColor)
    StringButton.configure(bg=FieldColor, fg=TextColor)
    BytesButton.configure(bg=FieldColor, fg=TextColor)
    CopyButton.configure(bg=FieldColor, fg=TextColor)
    AboutButton.configure(bg=FieldColor, fg=TextColor)

def ThemeChanged(event):
    global Theme
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
        BGColor = "#000000" # Black
        TextColor = "#ff0000" # Red
        FieldColor = "#000000" # Black
        
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

# - Section A (Root, Frame)

Root = Interface.Tk()
Root.title("Vortex (VTX) Crypto VID: 1.0.0")
Root.iconbitmap("Vortex-Icon.ico")
Root.configure(bg="black")
Root.resizable(False, False)

HeaderFrame = LabelFrame(Root, bd=0, bg="black", fg="cyan", text="Author: WorldDstroyer, https://twitter.com/WorldDstroyer", width=200, height=275, padx=5, pady=5)
HeaderFrame.pack()
ButtonFrameA = LabelFrame(Root, bd=0, bg="black", fg="cyan", width=250, height=25, padx=5, pady=5)
ButtonFrameA.pack()
ButtonFrameB = LabelFrame(Root, bd=0, bg="black", fg="cyan", width=250, height=25, padx=5, pady=5)
ButtonFrameB.pack()
BottomFrame = LabelFrame(Root, bd=0, bg="black", fg="cyan", width=250, height=25, padx=5, pady=5)
BottomFrame.pack()
ExtraFrameA = LabelFrame(Root, bd=0, bg="black", fg="cyan", width=250, height=25, padx=5)
ExtraFrameA.pack()
ExtraFrameB = LabelFrame(Root, bd=0, bg="black", fg="cyan", width=250, height=25, padx=5, pady=5)
ExtraFrameB.pack()
FooterFrameA = LabelFrame(Root, bd=0, bg="black", fg="cyan", text="Theme Configuration (Order: BG, FG/Text, Button/Field)", width=250, height=25, padx=5, pady=5)
FooterFrameA.pack()
FooterFrameB = LabelFrame(Root, bd=0, bg="black", fg="cyan", width=250, height=25)
FooterFrameB.pack()

# - Section B (Label)

ThemeLabel = Interface.Label(FooterFrameA, bg="black", fg="cyan", font="Arial 12 bold", text="Theme:")
ThemeLabel.pack(side="left", fill=None, expand=False, anchor="w")

# Theme Dropdown
ThemeOptions = [
    "Vortex",
    "Terminal",
    "Sinister",
    "Solaris",
    "Crimson",
    "Sky",
    "Light",
    "Dark",
    "Custom",
]

Theme = StringVar()
Theme.set("Vortex")
ThemeList = InterfaceExtension.Combobox(FooterFrameA, value=ThemeOptions)
ThemeList.current(0)
ThemeList.bind("<<ComboboxSelected>>", ThemeChanged)
ThemeList.configure(font="Arial 12 bold", width=8)
ThemeList.pack(side="left", fill=None, expand=False, anchor="w"
#, pady=5
)

InputLabel = Interface.Label(HeaderFrame, bg="black", fg="cyan", font="Arial 12 bold", text="Input Data:")
InputLabel.pack(side="top", fill=None, expand=False, anchor="n")
# Label-Divider
OutputLabel = Interface.Label(BottomFrame, bg="black", fg="cyan", font="Arial 12 bold", text="Output Data:")
OutputLabel.pack(side="top", fill=None, expand=False, anchor="n")
# Label-Divider
LengthLabel = Interface.Label(ExtraFrameA, bg="black", fg="cyan", font="Arial 12 bold", text="Length:")
LengthLabel.pack(side="top", fill=None, expand=False, anchor="n")

# - Section C (Text, Entry)

VectorEntry = Interface.Entry(HeaderFrame, width=45)
VectorEntry.configure(bg="black", fg="cyan", font="Arial 12 bold")
VectorEntry.pack(side="bottom", fill=None, expand=False, anchor="s", pady=5)

# # # # #
VectorLabel = Interface.Label(HeaderFrame, bg="black", fg="cyan", font="Arial 12 bold", text="Initialization Vector (Seed):")
VectorLabel.pack(side="bottom", fill=None, expand=False, anchor="s")
# # # # #

InputText = Interface.Text(HeaderFrame, bg="black", fg="cyan", font="Arial 12 bold", wrap=WORD, width=45, height=10)
InputText.pack(side="top", fill=None, expand=False, anchor="n", pady=5)
# Entry-Divider
KeyEntry = Interface.Entry(HeaderFrame, width=45)
KeyEntry.configure(bg="black", fg="cyan", font="Arial 12 bold", show="•")
KeyEntry.pack(side="bottom", fill=None, expand=False, anchor="s", pady=5)

# # # # #
KeyLabel = Interface.Label(HeaderFrame, bg="black", fg="cyan", font="Arial 12 bold", text="Cipher Key:")
KeyLabel.pack(side="bottom", fill=None, expand=False, anchor="s")
# # # # #

OutputText = Interface.Text(BottomFrame, bg="black", fg="cyan", font="Arial 12 bold", wrap=WORD, width=45, height=10)
OutputText.pack(side="bottom", fill=None, expand=False, anchor="s")
# Entry-Divider
LengthEntry = Interface.Entry(ExtraFrameA, bg="black", fg="cyan", font="Arial 12 bold", justify="center", width=8)
LengthEntry.pack(side="top", fill=None, expand=False, anchor="n")

BGEntry = Interface.Entry(FooterFrameA, bg="black", fg="cyan", font="Arial 12 bold", justify="center", width=9)
BGEntry.pack(side="left", fill=None, expand=False, anchor="w")

FGEntry = Interface.Entry(FooterFrameA, bg="black", fg="cyan", font="Arial 12 bold", justify="center", width=9)
FGEntry.pack(side="left", fill=None, expand=False, anchor="w")

FieldEntry = Interface.Entry(FooterFrameA, bg="black", fg="cyan", font="Arial 12 bold", justify="center", width=9)
FieldEntry.pack(side="left", fill=None, expand=False, anchor="w")

# - Section D (Button)

# "Encrypt" Button
EncryptButton = Interface.Button(ButtonFrameA, bg="black", fg="cyan", font="Arial 12 bold", text="Encrypt", command=Encrypt)
EncryptButton.pack(side="left", fill=None, expand=False, anchor="w")
#

# "Decrypt" Button
DecryptButton = Interface.Button(ButtonFrameA, bg="black", fg="cyan", font="Arial 12 bold", text="Decrypt", command=Decrypt)
DecryptButton.pack(side="left", fill=None, expand=False, anchor="w")
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

# "Hash | Trim Key (SHA-512)" Button
HashButton = Interface.Button(ButtonFrameB, bg="black", fg="cyan", font="Arial 12 bold", text="Hash | Trim Key (SHA-512)", command=KeyHash)
HashButton.pack(side="left", fill=None, expand=False, anchor="w")
#

# "Open" Button
OpenButton = Interface.Button(ButtonFrameB, bg="black", fg="cyan", font="Arial 12 bold", text="Open", command=OpenData)
OpenButton.pack(side="left", fill=None, expand=False, anchor="w")
#

# "Save" Button
SaveButton = Interface.Button(ButtonFrameB, bg="black", fg="cyan", font="Arial 12 bold", text="Save", command=SaveData)
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
AboutButton = Interface.Button(FooterFrameB, bg="black", fg="cyan", font="Arial 12 bold", text="About | Help", command=ProgramInfo)
AboutButton.pack(side="bottom", fill=None, expand=False, anchor="s")
#

Interface.mainloop()
