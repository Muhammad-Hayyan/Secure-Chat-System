#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include<cmath>
#include<ctime>
#include <openssl/evp.h>
#include <openssl/rand.h>
using namespace std;

int sock;
int p=17, a=4;

// Define AES block size
#define AES_BLOCK_SIZE 16

// Convert binary data to hex string
void bin_to_hex(const unsigned char *bin, int bin_len, char *hex) {
    for (int i = 0; i < bin_len; ++i) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0';  // Null-terminate
}

// Convert hex string back to binary data
void hex_to_bin(const char *hex, unsigned char *bin, int bin_len) {
    for (int i = 0; i < bin_len; ++i) {
        sscanf(hex + 2 * i, "%2hhx", &bin[i]);
    }
}

// Function to handle errors
void handleErrors(const char *msg) {
    cerr << msg << endl;
    exit(1);
}

// Resize the user-generated key to 128 bits (16 bytes)
void resize_key(unsigned char *key, int key_len, unsigned char *resized_key) {
    if (key_len < 16) {
        memcpy(resized_key, key, key_len);
        memset(resized_key + key_len, 0, 16 - key_len);
    } else if (key_len > 16) {
        memcpy(resized_key, key, 16);
    } else {
        memcpy(resized_key, key, 16);
    }
}

// AES-128 CBC encryption using EVP
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    if (!ctx) handleErrors("Failed to create context.");

    // Initialize the encryption operation with AES-128-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
        handleErrors("Encryption initialization failed.");

    // Perform the encryption
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        handleErrors("Encryption failed during update.");
    ciphertext_len = len;

    // Finalize the encryption (for padding)
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        handleErrors("Encryption failed during finalization.");
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// AES-128 CBC decryption using EVP
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;

    if (!ctx) handleErrors("Failed to create context.");

    // Initialize the decryption operation with AES-128-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
        handleErrors("Decryption initialization failed.");

    // Perform the decryption
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        handleErrors("Decryption failed during update.");
    plaintext_len = len;

    // Finalize the decryption (for removing padding)
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        handleErrors("Decryption failed during finalization.");
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
bool valid_pass(string pass)
{
    bool cap=0, small=0, num=0, spec=0;
    for(int i=0; i<pass.length(); i++)
    {
        if(pass[i] >= 65 && pass[i] <= 90)
        {
            cap=1;
        }
        if(pass[i] >= 97 && pass[i] <= 122)
        {
            small=1;
        }
        if(pass[i] >= 48 && pass[i] <= 57)
        {
            num=1;
        }
        if((pass[i] >= 33 && pass[i] <= 47) || (pass[i] >= 58 && pass[i] <= 64) || (pass[i] >= 91 && pass[i] <= 96) || (pass[i] >= 123 && pass[i] <= 126))
        {
            spec=1;
        }
    }
    if(cap==1 && small==1 && num==1 && spec==1)
        return 1;
    else
        return 0;
}

int DeffieHelman()
{
	srand(time(NULL));
	char buf[256];
	//************************************************** Deffie Hellman Key Exchange *************************************************************************       	
	//selecting kpr 'c'
	int c = (rand() % 8)+3;
	
	string temp;
	// Clear buffer and receive KpubA from server
	memset(buf, 0, sizeof(buf));
	recv(sock, buf, sizeof(buf), 0);
	temp = buf;
	int A = stoi(temp);
	
	
	//caculating kpub B
	long long int B = pow(a, c);
	B = B%p;
	string KpubB = to_string(B);
	
	// Sending KpubB to the server
	strcpy(buf, KpubB.c_str());
	send(sock, buf, sizeof(buf), 0);
		
	//Calculating the key (mutual key)
	long long int Kmutual = pow(A, c);
	Kmutual = Kmutual%p;
	if(Kmutual < 0)
		Kmutual = Kmutual + p;

	return Kmutual;
			
}
void create_socket()
{
    // create the socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    // setup an address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(8080);
    connect(sock, (struct sockaddr *) &server_address, sizeof(server_address));
}
string encrypt(string plain)						//Function to encrypt text using rot 47
{
	string cipher;
	for(int i=0; i<plain.length(); i++)
	{
		cipher += plain[i] + 47;
	}
	return cipher;
}
string decrypt(string cipher)						//function to decrypt
{
	string plain;
	for(int i=0; i<cipher.length(); i++)
	{
		plain += cipher[i] - 47;
	}
	return plain;
}
void EncAndSend(int client_socket, char message[], unsigned char aes_key[])
{
    char plaintext[128];
    unsigned char ciphertext[144];  // Buffer for ciphertext + IV
    char hex_ciphertext[288];       // Hex string (2x size of binary ciphertext)
    unsigned char iv[AES_BLOCK_SIZE];  // Temporary IV for this encryption
    int ciphertext_len;
    char buf[256];

    // Generate a new IV for each encryption
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        handleErrors("Failed to generate IV.");
    }

    // Encrypt the plaintext
    memset(ciphertext, 0, sizeof(ciphertext));
    strcpy(plaintext, message);
    ciphertext_len = aes_encrypt((unsigned char*)plaintext, strlen((char *)plaintext), aes_key, iv, ciphertext);

    // Append the IV to the end of the ciphertext
    memcpy(ciphertext + ciphertext_len, iv, AES_BLOCK_SIZE);  // Appending IV after ciphertext
    ciphertext_len += AES_BLOCK_SIZE;  // New ciphertext length includes the IV

    // Convert binary ciphertext to hex
    bin_to_hex(ciphertext, ciphertext_len, hex_ciphertext);

    // Send the hex-encoded ciphertext length first
    string ci_len = to_string(strlen(hex_ciphertext));
    memset(buf, 0, sizeof(buf));
    strcpy(buf, ci_len.c_str());
    send(client_socket, buf, sizeof(buf), 0);

    // Send the hex-encoded ciphertext
    send(client_socket, hex_ciphertext, strlen(hex_ciphertext), 0);
}
string RecvAndDec(int client_socket, unsigned char aes_key[])
{
    unsigned char ciphertext[144];   // Buffer to store the ciphertext + IV
    char hex_ciphertext[288];        // Hex string (2x size of binary ciphertext)
    unsigned char decryptedtext[128];
    unsigned char iv[AES_BLOCK_SIZE];  // Temporary IV for decryption
    int ciphertext_len;
    char buf[256];
    string pt;

    // Receive the ciphertext length first (hex length)
    recv(client_socket, buf, sizeof(buf), 0);  // Receiving hex-encoded ciphertext length
    string ci_len = buf;
    int hex_ciphertext_len = stoi(ci_len);

    // Receive the hex-encoded ciphertext
    memset(hex_ciphertext, 0, sizeof(hex_ciphertext));
    int bytes_received = recv(client_socket, hex_ciphertext, hex_ciphertext_len, 0);
    if (bytes_received <= 0) {
        handleErrors("Error receiving hex-encoded ciphertext.");
    }

    // Convert hex back to binary
    hex_to_bin(hex_ciphertext, ciphertext, hex_ciphertext_len / 2);
    ciphertext_len = (hex_ciphertext_len / 2) - AES_BLOCK_SIZE;  // Adjust length to exclude the IV

    // Extract the IV from the last 16 bytes of the received ciphertext
    memcpy(iv, ciphertext + ciphertext_len, AES_BLOCK_SIZE);  // Extract IV

    // Decrypt the ciphertext to recover the original plaintext
    int decryptedtext_len = aes_decrypt((unsigned char*)ciphertext, ciphertext_len, aes_key, iv, (unsigned char*)decryptedtext);

    // Null-terminate the decrypted text (since it's a string)
    decryptedtext[decryptedtext_len] = '\0';

    //pt = decryptedtext;
    pt = string(reinterpret_cast<char*>(decryptedtext), decryptedtext_len);
	return pt;
}

int main() 
{
    char buf[256];
    bool x=0;
    int key;
	string buf2;
    
    srand(time(NULL));

    //cout << "\n\t>>>>>>>>>> XYZ University Chat Client <<<<<<<<<<\n\n";
	cout<<"\n\033[93;1m-------------------------------------\033[0m\n";
    cout<< "\033[92;1m   ____ _     ___ _____ _   _ _____   \n";
    cout<< "  / ___| |   |_ _| ____| \\ | |_   _|  \n";
    cout<< " | |   | |    | ||  _| |  \\| | | |    \n";
    cout<< " | |___| |___ | || |___| |\\  | | |    \n";
    cout<< "  \\____|_____|___|_____|_| \\_| |_|    \033[0m\n";
	cout<<"\n\033[93;1m-------------------------------------\033[0m\n\n";
   
    
    // Create socket and connect to the server
    create_socket();
    
	cout<<"\n\033[92;1m Connected to the server successfully.\033[0m\n\n";
	// Clear buffer and receive response from server
    memset(buf, 0, sizeof(buf));
    recv(sock, buf, sizeof(buf), 0);
    if (strcmp(buf, "connected") == 0) {					//if server sent 'connected'
			key = DeffieHelman();
	}
	else
	{
		cout << "\n\033[91;1mUnable To Connect to Server.\033[0m\n";
	}
    
	string strkey = to_string(key);
	char user_key[16];
	strcpy(user_key, strkey.c_str());
	int user_key_len = strlen((char *)user_key);
	
	// Resize the user key to fit AES-128 (16 bytes)
    unsigned char aes_key[16];
    resize_key((unsigned char*)user_key, user_key_len, aes_key);
    
    // IV (Initialization Vector)
    char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes((unsigned char*)iv, AES_BLOCK_SIZE)) {
        handleErrors("Failed to generate IV.");
    }
   	//sending iv to server
    send(sock, iv, sizeof(iv), 0);
    
    // clear buffer and receive iv from client
	memset(buf, 0, sizeof(buf));
	int bytes_received = recv(sock, buf, AES_BLOCK_SIZE, 0);
	if (bytes_received != AES_BLOCK_SIZE) {
    		handleErrors("Error receiving IV.");
	}
    char dec_iv[AES_BLOCK_SIZE];
    memcpy(dec_iv, buf, AES_BLOCK_SIZE);

    
    
    // Example plaintext
    char plaintext[128];
    char ciphertext[128];   // Buffer to store the ciphertext
    char decryptedtext[128]; // Buffer to store the decrypted text
    int ciphertext_len;
  	int decryptedtext_len;

    string uname;
    while (true) {
        x=0;
        
		string ci_len;

		//receiving text and decyrpting it and storing in buf2
        buf2 = RecvAndDec(sock, aes_key);
		cout<<"\n"<<buf2<<endl;
        if(buf2 == "Server: \033[91;1mWrong Tries limit exceeded! Please Try again later.\033[0m")
        {
            break;
        }
        if(buf2 == "Server: \033[92;1m[✔] Login Successful.\033[0m")
        {
//**********************************************************************************************************************************************************
			// Get user input and send it to the server
			cout << "\n\033[93;1mPress any key to start chat : \033[0m";
			string message;
			getline(cin, message);
			memset(buf, 0, sizeof(buf));
			strcpy(buf, message.c_str());

			//encrypting the message to be sent
			EncAndSend(sock, buf, aes_key);

			key = DeffieHelman();
			strkey = to_string(key);
			uname = uname + strkey;				//appending username
			strkey = uname;
			memset(user_key, 0, sizeof(user_key));
			strcpy(user_key, strkey.c_str());
			user_key_len = strlen((char *)user_key);
	
			// Resize the user key to fit AES-128 (16 bytes)
    		memset(aes_key, 0, sizeof(aes_key));
    		resize_key((unsigned char*)user_key, user_key_len, aes_key);
			
			cout << "\n\t\033[92;1m[✔] Chat Started \033[0m\n\n";
			while(1)					//starting chat
			{
				// Send the message to the server
				cout<<"\n\033[93;1m[+] YOU : \033[0m";
				string message;
				getline(cin, message);
				strcpy(buf, message.c_str());
				//encrypting the message to be sent
        		EncAndSend(sock, buf, aes_key);
				
				if(message == "exit" || message == "Exit" || message == "EXIT")
				{
					cout << "\n\033[91;1m[+] Disconnecting ... \033[0m\n";
					x=1;
					break;
				}
				
				//receiving text and decyrpting it and storing in buf2
				buf2 = RecvAndDec(sock, aes_key);
				// if server sends "exit", close the connection
				if (buf2=="exit") 
				{
					cout << "\n\033[91;1mServer Disconnected.\033[0m\n";
					x=1;
					break;
				}
				cout<< "\n\033[92;1mServer : \033[0m";
				cout<<buf2<<endl;
									
			}
			
        }
        if(x==1)
        {
            break;
        }
        // Get user input and send it to the server
        cout << "You (Client): ";
        string message;
        getline(cin, message);
        memset(buf, 0, sizeof(buf));
        strcpy(buf, message.c_str());

        //encrypting the message to be sent
        EncAndSend(sock, buf, aes_key);

        // If the client sends "exit", terminate the chat
        if (message == "exit") {
            cout << "\n\033[91;1mYou disconnected from the server.\033[0m\n";
            break;
        }
        
		if(buf2== "Server: \t\033[93;1mPlease Enter Your Username : \033[0m\n")
        {
			uname = message;
		}
    }

    // Close the socket after communication
    EVP_cleanup();
    close(sock);

    return 0;
}
