# Secure-Chat-System
A Secure Chat System with Registration, Login, and  Encrypted Communication.

This project implements a secure chat system in C++ that allows users to register, log in, and communicate securely using encryption techniques. The system uses cryptographic methods like Diffie-Hellman for key exchange, SHA-256 for password hashing, and AES-128 for message encryption.

## Features

- **User Registration**: Users can create an account with a unique username and password.
- **User Login**: Users are authenticated with credentials provided during registration.
- **Encrypted Communication**: Messages between the client and server are encrypted using AES-128.
- **Secure Password Storage**: Passwords are hashed with SHA-256 and salted for security.
- **Diffie-Hellman Key Exchange**: Used for secure exchange of keys for encryption.

## How it Works

### Registration
- The client prompts the user to enter an email, username, and password.
- A shared secret key is generated using Diffie-Hellman key exchange.
- The client encrypts the email, username, and password with AES-128 using the shared key.
- The server decrypts the message, hashes the password with SHA-256 and a random salt, and stores it in `creds.txt` if the username is unique.

### Login
- The client sends a login request, and Diffie-Hellman key exchange is performed again.
- The client encrypts the username and password and sends it to the server.
- The server verifies the credentials by hashing the input password with the stored salt and comparing the result with the stored hash.

### Chat System
- After a successful login, the client and server exchange messages encrypted with AES-128 using a new key computed from Diffie-Hellman.
- The chat session ends when a user types "bye."

## Security Measures

- **SHA-256 Hashing**: Passwords are stored as secure hashes with unique salts.
- **AES-128 Encryption**: Messages between the client and server are encrypted.
- **Diffie-Hellman Key Exchange**: Ensures that encryption keys are securely exchanged without being exposed.
- **Log File**: A log file so that server can monitor any unusual activities.
- **Regex Pattern for Password**: A regex pattern for passwords and email to avoid weak passwords.

## File Structure

- `client.cpp`: Client-side code.
- `server.cpp`: Server-side code.
- `creds.txt`: An encrypted File with root permissions for storing usernames, hashed passwords, salts, and email addresses.
- `log.txt`: A file which is used to track the login and registration of users.
- `README.md`: Project documentation.

## Dependencies

- C++ Compiler (e.g., g++)
- OpenSSL library (for cryptographic operations)

## Usage

1. **Clone the repository**:
   ```bash
   git clone https://github.com/YourUsername/SecureChatSystem.git
2. **Compile the client and server**:
   ```bash
   g++ client.cpp -o client -lssl -lcrypto
   g++ server.cpp -o server -lssl -lcrypto
3. **Run the server**:
   ```bash
   ./server
4. **Run the client**:
   ```bash
   ./client

## Testing

- Functional testing has been done for registration, login, and encrypted chat.
- Network analysis (e.g., using Wireshark) confirms that all messages are encrypted during registration, login, and chat.

**Please mention if you face any issues.**


