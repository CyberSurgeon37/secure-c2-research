AES-GCM TCP Bind Shell

Project version: v1.0

Overview & Background: The purpose of this project was to demonstrate the development of a Python C2 implant with cleartext, then upgraded to AES-256 (ECB Mode), and finally AES-GCM. The project is intended to demonstrate a multi-threaded TCP Bind Shell which allows for code execution. Following the course Python 201 for Hackers on TCM Security Academy, and learning more about the Windows API and Pycryptodome during the process, Project 5 involved the development of an encrypted bind shell. The developer wanted to iterate on the protype presented in the class to advance it to involve AES-256-GCM to provide greater cryptographic integrity. This prototype provides greater resilience against replay attacks.   

Features:
- Multi-threaded architecture
- Key management
- Remote code execution capabilities
- Encrypted transport for confidentiality and cryptographic integrity
- Tamper evidence (bit-flipping and command injection mitigation)

Prerequisites
- Developed utilizing Python 3.14.2
- PyCryptoDome Library


Instructions

1. Start listener with the following command: 
python3 src/c2_implant.py -l 
2. Copy the encryption key displayed in the output
3. Enter victim IP address and encryption key generated
python3 src/c2_implant.py -c <TARGET_IP> -k <PASTE_KEY_HERE>
4. Execute commands (e.g., ipconfig, whoami)


Common Issues:
1. Make sure you installed pycryptodome
2. Ensure you are running the command from the right folder.
3. During testing, ensure you are allowing python through the firewall temporarily for testing in your lab environment.
4. Ensure you copied the key precisely.

Project structure: 
secure-c2-research/
├── src/
│   └── c2_implant.py        # Main AES-GCM implant source code
├── prototypes/
│   ├── basic_bind_shell.py  # Unencrypted bind shell
│   └── ecb_implant.py       # AES-ECB implementation
├── requirements.txt         # Project dependencies
└── README.md                # Documentation