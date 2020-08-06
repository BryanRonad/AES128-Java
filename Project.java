package myproject;

import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class Project{
	
private static final String UNI = "UTF-8";

public static void main(String ar[])
{
	try
	{
		int c;
		SecretKey secKey = getSecretEncryptionKey(); 		//Generates a random key 
		
		byte[] IV = new byte[16];							//Generates a random IV (Initializing Vector)
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
        
        do {
        System.out.println("\n\nData Encryption and Decryption\n");
    	System.out.println("\n****MENU****");	
    	System.out.println("1. Encrypt");	
    	System.out.println("2. Decrypt");
    	System.out.println("3. Exit");
    	System.out.println("*************");
    	System.out.println("\nEnter your choice");
    	Scanner sc=new Scanner(System.in);
    	c=sc.nextInt();
        
    	switch(c)
    	{
    	case 1: String s1=getString();
    			System.out.println("\nOriginal Text : "+s1);
    			byte[] cipherText1 = encrypt(s1.getBytes(UNI),secKey,IV);					//Calling encryption method
    			System.out.println("Encrpted text (Base64): "+bytesToBase(cipherText1));	//Displaying CipherText AFTER encoding to Base64
    			sc.nextLine();																//'Eats' the dangling \n
    			sc.nextLine();																//Trick to wait for a keypress before continuing
    			break;
    	case 2: String s2=getString();
    			System.out.println("\nEncrypted Text (Base64): "+s2);						
    			byte[] cipherText2 = Base64.getDecoder().decode(s2);						//Decoding Base64 to byte array
    			String decryptedText = decrypt(cipherText2,secKey,IV);						//Calling decryption method 
    	        System.out.println("Decrypted Text : "+decryptedText);
    	        sc.nextLine();																//'Eats' the dangling \n
    	        sc.nextLine();																//Trick to wait for a keypress before continuing
    	        break;
    	case 3: break;		
    	}
        }while(c!=3);
	 }catch(Exception e)
	{
		System.out.println("F\n"+e);
	}
}

public static SecretKey getSecretEncryptionKey() throws Exception{		//Method to generate a secure 128 bit random key 
    KeyGenerator generator = KeyGenerator.getInstance("AES");			//Creates a KeyGenerator instance in AES mode
    generator.init(128);												//Initializes to 128 bit
    SecretKey key = generator.generateKey();							//Generates key and stores it in key
    return key;
}


public static String bytesToBase(byte[] temp)				//Method to encode unreadable byte array to readable Base64 string
{
	String encoded = Base64.getEncoder().encodeToString(temp);			
	return encoded;
}

public static String baseToByte(byte[] temp)				//Method to decode readable Base64 string to unreadable byte array 
{
	String decoded = new String(Base64.getDecoder().decode(temp));
	return decoded;
}

public static String getString()
{
	String st;
	System.out.println("\nEnter text (String): ");
	Scanner sc= new Scanner(System.in);
	st=sc.nextLine();
	return st;
}


public static byte[] encrypt(byte[] plaintext,SecretKey key,byte[] IV ) throws Exception
{
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");					//Get Cipher Instance
    SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");			//Create SecretKeySpec 
    IvParameterSpec ivSpec = new IvParameterSpec(IV);							//Create IvParameterSpec
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);							//Initialize Cipher to ENCRYPT_MODE
    byte[] cipherText = cipher.doFinal(plaintext);							  	//Perform Encryption
    return cipherText;
}

public static String decrypt (byte[] cipherText, SecretKey key,byte[] IV) throws Exception
{
    
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");				//Get Cipher Instance
    SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");		//Create SecretKeySpec
    IvParameterSpec ivSpec = new IvParameterSpec(IV);						//Create IvParameterSpec 
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);						//Initialize Cipher to DECRYPT_MODE
    byte[] decryptedText = cipher.doFinal(cipherText);						//Perform Decryption
    return new String(decryptedText);
}
}