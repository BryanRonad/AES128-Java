package myproject;

import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.file.*;

public class Project{
	
private static final String UNI = "UTF-8";
static String FILEPATH = "D:\\KeyShitFiles\\";
static String KEYSTOREPATH = "D:\\KeyShitFiles\\";


public static void main(String ar[])
{
	try
	{
		int c;
		SecretKey secKey = getSecretEncryptionKey(); 																//Generates a random key only for current session

		byte[] IV = new byte[16];																					//Generates a random IV (Initializing Vector)
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
        
        do 
        {
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
    				System.out.println("\nOriginal Text : \n"+s1);
    				byte[] cipherText1 = encrypt(s1.getBytes(UNI),secKey,IV);										//Calling encryption method
    				byte[] totalCipherText = concatByteArrays(IV,cipherText1);										//Concatenate IV and user input to store together
    				System.out.println("Do you want to save encrypted data to a file? (y/n)");
    				char e = sc.next().charAt(0);
    				switch(e)
    				{
    				case 'y','Y': System.out.println("Enter desired file name (add .txt): ");
    						  	  sc.nextLine();
    						  	  String filename=sc.nextLine();
    						  	  infoToFile(bytesToBase(totalCipherText),filename);
    						  	  System.out.println("Data stored to a file. Location: "+FILEPATH);
    						  	  break;
    				case 'n','N': System.out.println("Encrpted text (Base64): "+bytesToBase(totalCipherText));		//Displaying combined CipherText AFTER encoding to Base64
    						  	  break;
    				default: System.out.println("Error, something went wrong :(");
    				}
    				System.out.println("Do you want to enter your secret key into a KeyStore? (recommended if you are going to terminate session before decryption)");
    				char f = sc.next().charAt(0);
    				if(f=='y'||f=='Y')
    				{
    							  System.out.println("Enter desired file name (add .jks): ");
    						  	  sc.nextLine();
    						  	  String filenamejks=sc.nextLine();
    						  	  System.out.println("Set a password for the KeyStore: ");
    						  	  String keyStorePassword = sc.nextLine();
    						  	  KeyStoreMaterial ksm = new KeyStoreMaterial(secKey,keyStorePassword,filenamejks);
    						  	  ksm.inputKeyStore();
    				}else if(f=='n'||f=='N')
    				{
    					break;
    				}else {
    					System.out.println("Error");
    				}
    				sc.nextLine();																					//Trick to wait for a keypress before continuing
    				break;
    		case 2: 	
    					System.out.println("Do you want to read your secret key from a KeyStore? (mandatory if your desired key is from another session)");
    					char g = sc.next().charAt(0);
    					if(g=='y'||g=='Y')
    					{
    						 System.out.println("Enter file name (add .jks): ");
						  	 sc.nextLine();
						  	 String filenamejks=sc.nextLine();
						  	System.out.println("Enter password for the KeyStore: ");
						  	String keyStorePassword = sc.nextLine();
						  	System.out.println("Enter alias of your key: ");
						  	String keyAlias = sc.nextLine();
						  	KeyStoreMaterial ksm = new KeyStoreMaterial(keyAlias,keyStorePassword,filenamejks);
						  	ksm.readKeyStore();	
						  	secKey=ksm.myKey;
						  	System.out.println(ksm.myKey);
    					}else if(g=='n'||g=='N')
    					{
    						
    					}else
    					{
    						System.out.println("Error.");
    					}
						
				
    					System.out.println("1. Enter encrypted data directly\n2. Choose a file containing encrypted data\n");
    					int d = sc.nextInt();
    					if(d==1)
    						{
    							String s2=getString();
    							System.out.println("\nEncrypted Text (Base64): "+s2);						
    							byte[] cipherText2 = Base64.getDecoder().decode(s2);					//Decoding Base64 to byte array
    							if (g=='y'||g=='Y')
    							{
    								String decrypted = decrypt(cipherText2,secKey,IV);					//Calling decryption method
    								System.out.println("Decrypted Text : "+decrypted);
    							}
    							else
    							{
    								String decrypted = decrypt(cipherText2,secKey,IV);					//Calling decryption method
    								System.out.println("Decrypted Text : "+decrypted);
    							}
    							sc.nextLine();
    						}else if (d==2){
    							
    								System.out.println("Enter the file name you want to decrpyt from (add .txt): ");
    								sc.nextLine();
    								String filename=sc.nextLine();
    								String raw = infoFromFile(filename);
    								byte[] rawByte = Base64.getDecoder().decode(raw);
    								byte[] IV1 = Arrays.copyOfRange(rawByte, 0, 16);  
    								byte[] cipherText2 = Arrays.copyOfRange(rawByte, 16, rawByte.length); 
    								if (g=='y'||g=='Y')
    								{
    									String decrypted = decrypt(cipherText2,secKey,IV1);					//Calling decryption method
    								  	System.out.println("Decrypted Text : "+decrypted);
    								}
    								else
    								{
    									String decrypted = decrypt(cipherText2,secKey,IV1);					//Calling decryption method
    								  	System.out.println("Decrypted Text : "+decrypted);
    								}
    						}else
    						{
    							System.out.println("Error");
    						}
    						sc.nextLine();																	//Trick to wait for a keypress before continuing
    						break;
    		case 3: break;		
    		}
    	}while(c!=3);
	 }
    catch(Exception e)
	{
    	e.printStackTrace();
		System.out.println("F\n"+e);
	}
}


public static SecretKey getSecretEncryptionKey() throws Exception{		//Method to generate a secure 128 bit random key 
    KeyGenerator generator = KeyGenerator.getInstance("AES");			//Creates a KeyGenerator instance in AES mode
    generator.init(128);												//Initializes to 128 bit
    SecretKey key = generator.generateKey();							//Generates key and stores it in key
    return key;
}


public static String bytesToBase(byte[] temp)							//Method to encode unreadable byte array to readable Base64 string
{
	String encoded = Base64.getEncoder().encodeToString(temp);			
	return encoded;
}

public static String baseToByte(String temp)							//Method to decode readable Base64 string to unreadable byte array 
{
	String decoded = new String(Base64.getDecoder().decode(temp));
	return decoded;
}

public static byte[] concatByteArrays(byte[] IV, byte[] cipherText)  throws IOException
{
	ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
	outputStream.write(IV);
	outputStream.write(cipherText);
	byte c[] = outputStream.toByteArray();
	return c;
}

public static String getString()
{
	String st;
	System.out.println("\nEnter text (String): ");
	Scanner sc= new Scanner(System.in);
	st=sc.nextLine();
	return st;
}

public static void infoToFile(String cipherText, String filename)
{	
	try { 
			File file = new File(FILEPATH+filename); 
			FileWriter fileWriter = new FileWriter(file); 					// Initialize a pointer in file using OutputStream 
			fileWriter.write(cipherText); 									// Starts writing the bytes in it
			fileWriter.flush();												//Flushes the buffer 
            fileWriter.close(); 											// Close the file 
    } 
	catch (Exception e) { 
        System.out.println("Exception: " + e); 
    } 
}

public static String infoFromFile(String filename)
{
	try {  
		Path path = Paths.get(FILEPATH+filename);
		byte[] bytes = Files.readAllBytes(path);
		String st = new String(bytes,UNI);
		return st;
	} 
	catch (Exception e) { 
		System.out.println("Exception: " + e); 
		return null;
	}
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
    
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");					//Get Cipher Instance
    SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");			//Create SecretKeySpec
    IvParameterSpec ivSpec = new IvParameterSpec(IV);							//Create IvParameterSpec 
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);							//Initialize Cipher to DECRYPT_MODE
    byte[] decryptedText = cipher.doFinal(cipherText);							//Perform Decryption
    return new String(decryptedText,UNI);
}

public static class KeyStoreMaterial{
	public String filename;
	public String password;
	public String alias;
	public SecretKey myKey;
	public char[] pwdArray;
	
	KeyStoreMaterial(SecretKey mySecretKey, String keyStorePassword, String filename){
		this.filename=filename;
		this.password=keyStorePassword;
		this.myKey= mySecretKey;
	}
	
	KeyStoreMaterial(String alias,String keyStorePassword, String filename){
		this.filename=filename;
		this.password=keyStorePassword;
		this.alias=alias;		
	}
	public void inputKeyStore() {
		try
		{
		KeyStore ks = KeyStore.getInstance("JCEKS");
		this.pwdArray = this.password.toCharArray();
		ks.load(null, this.pwdArray);												// Save the keyStore
		System.out.println("Enter an alias for the key");
		Scanner oc = new Scanner(System.in);
		this.alias = oc.nextLine();
		ks.setKeyEntry(this.alias, this.myKey, this.pwdArray,null);
		OutputStream writeStream =new FileOutputStream(KEYSTOREPATH+filename);
		ks.store(writeStream,this.pwdArray);
		System.out.println("KeyStore successfully created");
		}catch(Exception e)
		{
			e.printStackTrace();
			System.out.println("F (KeystoreWrite)\n"+e);
		}
	}

	public void readKeyStore(){
		try
		{
		KeyStore ks = KeyStore.getInstance("JCEKS");
		InputStream is = new FileInputStream(KEYSTOREPATH+this.filename);
		this.pwdArray = this.password.toCharArray();
		ks.load(is, this.pwdArray);
		SecretKey key = (SecretKey)ks.getKey(this.alias, this.pwdArray);
		this.myKey = key;	
		}catch(Exception e)
		{
			e.printStackTrace();
			System.out.println("F (KeystoreRead)\n"+e);
		}
	}
}
}

