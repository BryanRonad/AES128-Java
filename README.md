# AES128-Java
A simple program for encrypting and decrypting data using AES 128 in Java



Logs:
6/8/2020 - Completed basic functionality 
	   *User input for encryption
	   *Session limited key and IV without file output and retention

7/8/2020 - Completed File I/O
	   *Encrypted data stored to text file after being appended to IV (Both in byte[])
	   *Encoding to Base64
	   *Retrieval from file during decrypted
	   *Decoding the Base64 string to byte[]
	   *Copying first 16 characters of the byte[] as IV 
	   *Copying rest of the characters of the byte[] as cipherText

		
	   