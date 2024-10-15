#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdlib>
#include<iomanip>
#include<fstream>
#include<ctime>
#include<cmath>
#include<chrono>
//libraries for hashing
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>

using namespace std;

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
void handleErrors(const char *msg) 
{
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


int DeffieHelman(int client_socket)
{
	char buf[256];
	srand(time(NULL));
	// *********************************************************** Deffie Hellman Key Exchange ************************************************************
	//Now exchanging keys

	//selecting kpr 's' (servers private key)
	int s = (rand() % 10)+3;

	
	//caculating kpub A
	long long int A = pow(a, s);
	A = A%p;
	string KpubA = to_string(A);
	
	// Sending KprA to the client
	strcpy(buf, KpubA.c_str());
	send(client_socket, buf, sizeof(buf), 0);
	
	// clear buffer and receive B from client
	memset(buf, 0, sizeof(buf));
	recv(client_socket, buf, sizeof(buf), 0);
	
	string temp = buf;
	int B = stoi(temp);
	
	//Calculating the key (mutual key)
	long long int Kmutual = pow(B, s);
	Kmutual = Kmutual%p;
	if(Kmutual < 0)
		Kmutual = Kmutual + p;
		
	return Kmutual;

}
// Function to generate a random salt
string generateSalt(size_t length = 16) {
    unsigned char salt[length];
    RAND_bytes(salt, length);  // Generate random bytes for the salt

    stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)salt[i];
    }

    return ss.str();
}

// Function to hash password with salt using SHA-256 and EVP API
string sha256(const string& password, const string& salt) {
    string saltedPassword = password + salt;  // Combine password and salt

    EVP_MD_CTX* context = EVP_MD_CTX_new();  // Create the message digest context
    const EVP_MD* md = EVP_sha256();         // Get the SHA-256 message digest

    if (context == nullptr || md == nullptr) {
        return "";
    }

    // Initialize, update, and finalize the hashing process
    if (EVP_DigestInit_ex(context, md, nullptr) != 1) {
        EVP_MD_CTX_free(context);
        return "";
    }
    if (EVP_DigestUpdate(context, saltedPassword.c_str(), saltedPassword.size()) != 1) {
        EVP_MD_CTX_free(context);
        return "";
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (EVP_DigestFinal_ex(context, hash, &lengthOfHash) != 1) {
        EVP_MD_CTX_free(context);
        return "";
    }

    EVP_MD_CTX_free(context);

    // Convert the hash to a hexadecimal string
    stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}
string rot13(string input) 					//for encrypting the file
{
    for (int i = 0; i < input.length(); ++i) 
	{
        if (isalpha(input[i])) 
		{
            if (islower(input[i])) 
			{
                input[i] = (input[i] - 'a' + 13) % 26 + 'a';
            } 
			else if (isupper(input[i])) 
			{
                input[i] = (input[i] - 'A' + 13) % 26 + 'A';
            }
        }
    }
    return input;
}
void write(string e, string uname, string hash, string salt)			//Function to write creds to file
{
	ofstream fout;
	fout.open("creds.txt" , ios::app);
	fout<<rot13(e)<<"\t";
	fout<<rot13(uname)<<"\t";
	fout<<hash<<"\t";
	fout<<salt<<"\n";
	fout.close();
	
	cout<<"\n\033[92;1m[✔] Client has been registered successfully.\033[0m\n\n";
}
bool checkUnique(string uname)					//Function to check for uniqueness of username
{
	string temp;
	ifstream fin;
	fin.open("creds.txt", ios::in);
	do
	{
		getline(fin, temp, '\t');
		getline(fin, temp, '\t');
		if(temp == uname)
		{
			fin.close();
			return 0;
		}
		else
		{
			getline(fin, temp);
		}
	}while(!fin.eof());
	
	fin.close();
	return 1;
	
}
bool isPrime(int n) 					//function to check for prime number
{
  
    if (n <= 1) {
        return false;
    }

    for (int i = 2; i < n; i++) 
    {
        if (n % i == 0) {
            return false;
        }
    }

    return true;
}
string returnSalt(string uname)
{
	string temp;
	bool x=0;
	ifstream fin;
	fin.open("creds.txt", ios::in);
	do
	{
		x=0;
		getline(fin, temp, '\t');
		getline(fin, temp, '\t');
		if(temp == uname)
		{
			getline(fin, temp, '\t');
			getline(fin, temp, '\n');
			fin.close();
			return temp;					//returns hash
		}
		else
		{
			getline(fin, temp);
			x=1;
		}
	}while(!fin.eof());
	
	fin.close();
	temp = "Not Found";
	return temp;
}	
bool login(string uname, string hash)					
{
	string temp;
	ifstream fin;
	fin.open("creds.txt", ios::in);
	do
	{
		getline(fin, temp, '\t');
		getline(fin, temp, '\t');
		temp = rot13(temp);					//first decrypting the file
		if(temp == uname)
		{
			getline(fin, temp, '\t');
			if(hash == temp)
			{
				fin.close();
				return 1;
			}
			else
			{
				fin.close();
				return 0;
			}
		}
		else
		{
			getline(fin, temp);
		}
	}while(!fin.eof());
	
	fin.close();
	return 0;

}

bool ValidEmail(string email)
{
	string regex = "@gmail.com";
	string temp;
	char tempchar;
	int i=0;
	for(; i<email.length(); i++)
	{
		if(email[i] == '@')
		{
			break;
		}
	}
	if(email[i] == '@')
	{
		temp = email[i];
		for(; i<email.length(); i++)
		{
			if(email[i] == '@')
			{

			}
			else
			{
				temp = temp+email[i];
			}
		}
		if(temp == regex)
			return 1;
		else
			return 0;
	}
	else
		return 0;

}
bool ValidPass(string pass)
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
void UpdateLog(string uname, int i)			//Function to write creds to file
{
	// Get current time as a time_point
    auto currentTime = chrono::system_clock::now();
    // Convert to time_t to get a calendar time
    time_t timeNow = chrono::system_clock::to_time_t(currentTime);
    // Convert to a readable format
   // cout << "Current time: " << ctime(&timeNow);
	ofstream fout;
	if(i == 1)
	{
		fout.open("log.txt" , ios::app);
		fout<<"Client "<<uname<<" logged in on "<<ctime(&timeNow)<<"\n";
		fout.close();
	}
	
	else
	{
		fout.open("log.txt" , ios::app);
		fout<<"Client with username "<<uname<<" registered on "<<ctime(&timeNow)<<"\n";
		fout.close();
	}
	
	
}
int main() {
	bool x=0, x2=0, x3=0, x4=0;
	string uname, email, pass;
    char buf[256];
	string buf2;
    char message[256] = "Server: ";
    string menu1 = "\n\t[1] Login\n"
                "\n\t[2] Register\n"
                "\n\n\033[93;1m[+] Please select any of the option from above (1-2) \033[0m: ";
    srand(time(NULL));
   // cout << "\n\t>>>>>>>>>> XYZ University Chat Server <<<<<<<<<<\n\n";
    cout<<"\n\033[93;1m----------------------------------------\033[0m\n";
    cout << "\033[92;1m  ____  _____ ______     _______ ____  \n";
    cout << " / ___|| ____|  _ \\ \\   / / ____|  _ \\ \n";
    cout << " \\___ \\|  _| | |_) \\ \\ / /|  _| | |_) |\n";
    cout << "  ___) | |___|  _ < \\ V / | |___|  _ < \n";
    cout << " |____/|_____|_| \\_\\ \\_/  |_____|_| \\_\\ \n\033[0m";
	cout<<"\n\033[93;1m-----------------------------------------\033[0m\n\n";
    cout<<"\n\033[93;1m[+] Waiting for any client to connect. \033[0m\n\n";
    srand(time(NULL));
    // create the server socket
    int server_socket;
    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    // define the server address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080);
    server_address.sin_addr.s_addr = INADDR_ANY;

    // bind the socket to the specified IP and port
    bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address));
    listen(server_socket, 5);
    while (1) {
        // accept incoming connections
        int client_socket;
        client_socket = accept(server_socket, NULL, NULL);

        // create a new process to handle the client
        pid_t new_pid;
        new_pid = fork();
        if (new_pid == -1) {
            // error occurred while forking
            cout << "Error! Unable to fork process.\n";
        } else if (new_pid == 0) {
            // child process handles the client
            //sending message connected to client
            string msg_con = "connected";
            strcpy(buf, msg_con.c_str());
            send(client_socket, buf, sizeof(buf), 0);
            memset(buf, 0, sizeof(buf));
            
            cout<<"\n\033[92;1m[✔] A Client has been connected to the server.\033[0m\n\n";
            int key = DeffieHelman(client_socket);					//exchanging keys using deffiehelman
            	
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
   			
   			// clear buffer and receive iv from client
		    memset(buf, 0, sizeof(buf));
		    int bytes_received = recv(client_socket, buf, AES_BLOCK_SIZE, 0);
			if (bytes_received != AES_BLOCK_SIZE) {
    				handleErrors("Error receiving IV.");
			}
		    char dec_iv[AES_BLOCK_SIZE];
		    memcpy(dec_iv, buf, AES_BLOCK_SIZE);
		    
		    //sending iv to client
    		send(client_socket, iv, sizeof(iv), 0);
    		
			char plaintext[128];
   			char ciphertext[128];   // Buffer to store the ciphertext
    		char decryptedtext[128]; // Buffer to store the decrypted text
  			int ciphertext_len;
  			int decryptedtext_len;
    

            cout<<"\n\033[92;1m[✔] Keys Exchanged\033[0m\n";
            while (true) {
                char message[256] = "Server: ";
                strcpy(message + 8, menu1.c_str()); // append the response after "Server: "
				EncAndSend(client_socket, message, aes_key);
                
                cout<<"\n\033[92;1m[✔] Sending options to the client\033[0m\n";
                
                do								//to check for invalid output
                {
		            cout<<"\n\033[93;1m[+] Waiting for clients response ... \033[0m\n\n";
		           
		            //Decrypting received text
					string ci_len;
					buf2 = RecvAndDec(client_socket, aes_key);

		            // if client sends "exit", close the connection
		            if (buf2 == "exit") 
					{
		                cout << "\n\033[91;1mClient disconnected.\033[0m\n";
		                x=1;
		                break;
					}
		            cout << "\nClient: " << buf2 << endl;
		            
		            if(buf2 == "1")							//login
		            {		
							int try_count=0;			//for counting wrong tries
				        	//promting client to enter username
				        	string msg1 = "\t\033[93;1mPlease Enter Your Username : \033[0m\n";
				        do
				        {
				        	x2=0;	
				        	strcpy(message + 8, msg1.c_str()); // append the response after "Server: "
						   	EncAndSend(client_socket, message, aes_key);
   				 			
						    cout<<"\n\033[92;1m[✔] Promting client to enter username...\033[0m\n";
						    cout<<"\n\033[93;1m[+] Waiting for clients response ... \033[0m\n\n";
						    buf2 = RecvAndDec(client_socket, aes_key);

							// if client sends "exit", close the connection
							if (buf2 == "exit") 
							{
								cout << "\n\033[91;1mClient disconnected.\033[0m\n";
								x=1;
								break;
							}
							cout << "\nClient: " << buf2 << endl;
						    uname = buf2;							//copying buf to email
						    
						    //promting client to enter a password
						    msg1 = "\t\033[93;1mPlease enter your Password : \033[0m\n";
						    strcpy(message + 8, msg1.c_str()); // append the response after "Server: "
						   	EncAndSend(client_socket, message, aes_key);
   				 			
						    cout<<"\n\033[92;1m[✔] Promting client to enter a password..\033[0m\n";
						    cout<<"\n\033[93;1m[+] Waiting for clients response ... \033[0m\n\n";
						    
						    buf2 = RecvAndDec(client_socket, aes_key);

							// if client sends "exit", close the connection
							if (buf2 == "exit") 
							{
								cout << "\n\033[91;1mClient disconnected.\033[0m\n";
								x=1;
								break;
							}
							cout << "\nClient: " << buf2 << endl;
						    pass = buf2;
						    
						    string salt = returnSalt(rot13(uname));					//retrieving corresponding user salt from file
						    string hash = sha256(pass, salt);				//hashing the entered password
						    
						    //checking credentials
						    cout<<"\n\033[93;1m[+] Checking if credentials are correct ...\033[0m\n";
						    if(login(uname, hash) == 1)
						    {
						    	cout<<"\n\033[92;1m[✔] Credentials Correct. Client logged in successfully.\033[0m\n";
						    	msg1= "\033[92;1m[✔] Login Successful.\033[0m";
						    	strcpy(message + 8, msg1.c_str()); // append the response after "Server: "
						    	EncAndSend(client_socket, message, aes_key);
					    	
								buf2 = RecvAndDec(client_socket, aes_key);

								// if client sends "exit", close the connection
								if (buf2 == "exit") 
								{
									cout << "\n\033[91;1mClient disconnected.\033[0m\n";
									x=1;
									break;
								}
							

								key = DeffieHelman(client_socket);
					
								strkey = to_string(key);
								string uname1 = uname + strkey;				//appending uname
								strkey = uname1;
								memset(user_key, 0, sizeof(user_key));
								strcpy(user_key, strkey.c_str());
								user_key_len = strlen((char *)user_key);
	
								// Resize the user key to fit AES-128 (16 bytes)
    							memset(aes_key, 0, sizeof(aes_key));
    							resize_key((unsigned char*)user_key, user_key_len, aes_key); 
    							
								UpdateLog(uname, 1);			//updating log file
								cout<<"\n\033[92;1m[✔] Keys Exchanged\033[0m\n";
								cout<<"\n\033[92;1m[✔] Starting chat ... \033[0m\n\n";
								
//****************************************************************************************************************************************************
								
								while(1)					//starting chat
								{
									buf2 = RecvAndDec(client_socket, aes_key);

									// if client sends "exit", close the connection
									if (buf2 == "exit") 
									{
										cout << "\n\033[91;1mClient disconnected.\033[0m\n";
										x=1;
										break;
									}
									cout<< "\n\033[92;1m[+] "<<uname<<" : \033[0m";
									cout<<buf2<<endl;
									
									string msg;
									cout<<"\n\033[93;1m[+] Server : \033[0m";
									getline(cin,  msg);
									memset(buf, 0, sizeof(buf));
									strcpy(buf, msg.c_str()); // append the response after "Server: "
									EncAndSend(client_socket, buf, aes_key);
									
									if(msg == "exit" || msg == "Exit" || msg == "EXIT")
									{
										cout << "\n\033[91;1m[+] Disconnecting ... \033[0m\n";
										x=1;
										break;
									}
									
								}
								//message = "Server: ";
										
						    }
						    else
						    {
						    	cout<<"\n\033[91;1m[✗] Username or Password incorrect! Promting to enter again\033[0m\n\n";
						    	//sending message to client
						    	msg1= "\033[91;1m[✗] Username or Password incorrect!\n \n\t\033[93;1mPlease Enter Your Username : \033[0m\n";
								try_count++;
								if(try_count>=5)
								{
									x4=1;
									break;
								}
						    	x2=1;
						    }
						 }while(x2==1);
						 
				        if(x==1)
				        	break;
				        
		            }
		            else if(buf2 == "2")						//register
		            {
		            	//promting client to enter email adress
		            	string msg1 = "\t\033[93;1mPlease Enter Your Email Address : \033[0m\n";
						do
						{
							x2=0;
							strcpy(message + 8, msg1.c_str()); // append the response after "Server: "
							EncAndSend(client_socket, message, aes_key);
							
							cout<<"\n\033[92;1m[✔] Promting client to enter an email address...\033[0m\n";
							cout<<"\n\033[93;1m[+] Waiting for clients response ... \033[0m\n\n";
							buf2 = RecvAndDec(client_socket, aes_key);

							// if client sends "exit", close the connection
							if (buf2 == "exit") 
							{
								cout << "\n\033[91;1mClient disconnected.\033[0m\n";
								x=1;
								break;
							}
							cout << "\nClient: " << buf2 << endl;
							email = buf2;							//copying buf to email

							cout<<"\n\033[93;1m[+] Checking for Validity of Email... \033[0m\n\n";
						    if(ValidEmail(email) == 0)				//checking validness
						    {
						    	cout<<"\n\033[91;1m[✗] Email is invalid. Promting client to enter Email again.\033[0m\n\n";
						    	//sending message to client
						    	msg1= "\t\033[91;1m[✗] Email is Invalid ! Please enter a valid Email.\033[0m\n";
								x2=1;
						    	
						    }
						    else						//if valid
						    {
						    	 cout<<"\n\033[92;1m[✔] Email is Valid \033[0m\n";
						    }

						}while(x2==1);

				        msg1= "\t\033[93;1mPlease Enter a unique Username : \033[0m\n";
				        do						//to check for uniqueness of username
				        {
				        	x2=0;
						    //promting client to enter username
						    strcpy(message + 8, msg1.c_str()); // append the response after "Server: "
							EncAndSend(client_socket, message, aes_key);
						    
							cout<<"\n\033[92;1m[✔] Promting client to select a username..\033[0m\n";
						    cout<<"\n\033[93;1m[+] Waiting for clients response ... \033[0m\n\n";
						    buf2 = RecvAndDec(client_socket, aes_key);

							// if client sends "exit", close the connection
							if (buf2 == "exit") 
							{
								cout << "\n\033[91;1mClient disconnected.\033[0m\n";
								x=1;
								break;
							}
							cout << "\nClient: " << buf2 << endl;
						    uname = buf2;
						    
						    cout<<"\n\033[93;1m[+] Checking for uniquness of the username... \033[0m\n\n";
						    if(checkUnique(rot13(uname)) == 0)				//checking uniqueness
						    {
						    	cout<<"\n\033[91;1m[✗] Username already exists. Promting client to enter username again.\033[0m\n\n";
						    	//sending message to client
						    	msg1= "\t\033[91;1m[✗] Username already exists! Please Enter a unique username.\033[0m\n";
								x2=1;
						    	
						    }
						    else						//if unique
						    {
						    	 cout<<"\n\033[92;1m[✔] Username is unique \033[0m\n";
						    }
						 }while(x2==1);
				        
				        //promting client to set a password
				        msg1 = "\t\033[93;1mPlease set your Password : \033[0m\n";
						bool valid_pass=0;
						do
						{
							valid_pass=0;
							strcpy(message + 8, msg1.c_str()); // append the response after "Server: "
							EncAndSend(client_socket, message, aes_key);
							
							cout<<"\n\033[92;1m[✔] Promting client to enter a password...\033[0m\n";
							cout<<"\n\033[93;1m[+] Waiting for clients response ... \033[0m\n\n";
							buf2 = RecvAndDec(client_socket, aes_key);

							// if client sends "exit", close the connection
							if (buf2 == "exit") 
							{
								cout << "\n\033[91;1mClient disconnected.\033[0m\n";
								x=1;
								break;
							}
							cout << "\nClient: " << buf2 << endl;
							pass = buf2;							//copying buf to pass

							cout<<"\n\033[93;1m[+] Checking for Validity of Password... \033[0m\n\n";
						    if(ValidPass(pass) == 0)				//checking validness
						    {
						    	cout<<"\n\033[91;1m[✗] Password is invalid. Promting client to enter Password again.\033[0m\n\n";
						    	//sending message to client
						    	msg1= "\t\033[91;1m[✗] Your Password must contain 'A'-'Z', 'a'-'z', 0-9 and a special character.\033[0m\n";
								valid_pass=1;
						    	
						    }
						    else						//if valid
						    {
						    	 cout<<"\n\033[92;1m[✔] Password is Valid \033[0m\n";
						    }

						}while(valid_pass==1);
				        
				        //generating salt
				        string salt = generateSalt();
				        //hashing the password
				     	string hash = sha256(pass, salt);
				     	//writing in creds file
				        write(email, uname, hash, salt);
						UpdateLog(uname, 2);
					}
		            else
		            {
		            	x=1;
		            	cout << "\n\033[91;1mClient selected invalid option. Promting client again.\033[0m\n";
		            	string error = "\033[91;1mInvalid option selected! Please select a valid option.\033[0m\n\n";
		            	strcpy(message + 8, error.c_str()); // append the response after "Server: "
				        EncAndSend(client_socket, message, aes_key);
		            	
		            }
                
                }while(x==1);
                
                if(x==1)
                {
                	break;
             	}
				if(x4==1)
				{
					cout << "\n\033[91;1m[✗] Client exceeded wrong try limit. Disconnecting Client...\033[0m\n";
					string msg1 = "\033[91;1mWrong Tries limit exceeded! Please Try again later.\033[0m";
					strcpy(message + 8, msg1.c_str());
					EncAndSend(client_socket, message, aes_key);
					break;
				}
            }

            // Close the client socket after communication
            close(client_socket);
            exit(0);
        } else {
            // parent process continues accepting clients
            close(client_socket);
        }
    }

    close(server_socket);

    return 0;
}
