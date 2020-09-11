# Vortex-Crypto
An open-source Python program for encrypting and decrypting data, using the PyCryptodome and TkInter libraries.

This document is a nearly identical mirror of the program's README.md file.

# ! Important Information !
- The Terms of Use for this program may be found at the bottom of this document.

The purpose of this program is to be able to access cryptographic standards, methods, and algorithms, (primarily encryption) in order to enhance the security of information.
This program utilizes the Python libraries PyCryptodome, and Tkinter, in order to assist in this purpose. While this program was made using the Windows 10 64-bit operating system, the included Python libraries (used to construct the graphical user interface) should function as normal on a Linux-based OS.

The SHA-512 hashes for every version of Vortex Crypto should be provided on its GitHub page (the executable, specifically). If you've downloaded this program, be absolutely sure that the hashes match, to verify that your executable is the same as the one provided. This can be done, on Windows, using the terminal command:
- certutil -hashfile Vortex-Crypto-1.0.0.exe sha512

Be advised that this program may trigger false positives with antivirus software. Particularly, the following antivirus software modules have been noted to routinely flag PyInstaller programs:
- Windows Defender
- AVG Antivirus
- McAfee Antivirus
These may be safely ignored, as long as the program has been downloaded directly from its GitHub repository, and the hashes have been verified to match.

# The security of the Advanced Encryption Standard (AES):
Advanced Encryption Standard, or "AES" for short, is a symmetric encryption algorithm, meaning that the same key is used to both encrypt plaintext data, and decrypt the resulting ciphertext. Like the majority of encryption algorithms, AES is a block cipher, with a fixed block size of 128 bits. However, key length is variable, and may be 16-Byte (AES-128), 24-Byte (AES-192), or 32-Byte (AES-256). In layman's terms, the "Byte" in this case refers to the length of the key, in characters. AES is made secure based on a few factors (see below).

# Factor I: Key Length
- As mentioned above, the key length for AES is variable. The longer it is, the more secure. There are complex math operations and calculations that have shown AES to be extremely secure, due to the astronomically large number of potential keys that may be necessary to bruteforce, should someone attempt to crack the ciphertext. Although variable, AES's key length is fixed, meaning that it cannot be any longer or shorter than the previously mentioned numbers of characters. Vortex Crypto attempts to alleviate this problem by providing a feature to "Hash | Trim" your input key. This will hash the key in SHA-512, and the resulting digest is trimmed to match the desired length (the trim length of which is determined by the AES size you have selected, i.e "AES-256" will trim the hash to 32-Bytes). This, theoretically, helps to strengthen the security of your encrypted data, and your key may be hashed as many times as you wish.

# Factor II: Cipher Mode
- An important factor that will determine the nature of the block cipher's encryption is its "mode" of operation. Vortex Crypto uses "Cipher Block Chaining" (CBC). This is likely the most commonly used mode for AES, as it eliminates a select few issues provided by other modes. CBC mode uses what is called an "initialization vector," or "IV", to randomize the digest of ciphertext. You can think of it almost like a "seed," of sorts. In order to decrypt ciphertext data that has been encrypted using CBC mode, you will need both the key, and the IV. There are a few other cipher modes that do not use an IV. To avoid having to memorize the IV for a digest, in Vortex Crypto, you can use the "Save" and "Open" features to save both the ciphertext, and the IV to a file. and then load it into the program again when needed. Vortex Crypto will save the file with the unique ".vtxc" extension, which is short for "Vortex Cipher File." It behaves like any other ".txt" file, however, this extension can be useful for distinguishing the file from a normal text document. It is okay to provide the IV following encryption, as it does not need to be a "secret" after the fact.

# Source:
https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

An original driving force behind the inception of this program was that I, WorldDstroyer, wanted a way to easily encrypt communications and local data to my leisure. It was also a big desire of mine to be able to write a program/tool that can be used as a legitimately secure locally-stored password manager. If there are any questions or concerns regarding this software, please contact me on any of the platforms listed below.

# Contact:
- Email: worlddstroyermail@gmail.com
- Twitter: https://twitter.com/WorldDstroyer
- Discord: https://discord.gg/YtsnpuW

By the way, I would be joyed if a real cryptography researcher were to analyze this program, and potentially provide helpful insight into the improvement of the performance and function of this tool's features.

# ! Terms of Use !
This program, its creator, contributing parties, and associated pieces of software are not to be liable for any potential or concurrent damages caused by the usage of this program, proper or improper. This program is not to be used for any purposes that violate the laws of the user's country and its jurisdiction, as well as any ordinances placed by associated governing bodies. This program may not be modified, changed, or altered in any way, as to enable harmful or illegal action. Likewise, this program may not be redistributed without the express permission of WorldDstroyer. This program does not promise or guarantee security, as its use relies entirely on the handling of the operating individual. Resources and citations are provided in this document that support, factually, the statistical and logistical findings of AES, as well as other cryptographic standards, to aid in supporting the claims made at the beginning of this document, with *known* information regarding said standards. This program abides by the laws of the United States of America, and it is to be used for exclusively legally-appropriate action when in the case of U.S. jurisdiction, as well as any other pertaining outside bodies. This program may not be used to develop or adapt the production of external tools or resources that may be used to conduct illegal activity. Mutually, this program, its creator, contributors, and any/all associated and related assets, tools, branding, or affiliated parties, may not be held liable when in the case of said production.
