package myproject;

import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class MyClass{
	
private static final String UNI = "UTF-8";

public static void main(String ar[])
{
	
	try 
	{
	int c;
	SecretKey key = generateKey("AES");
	Cipher cipher1;
	cipher1=Cipher.getInstance("AES/CBC/PKCS5Padding");
	do
	{
	c=input();
	switch(c)
	{
	case 1: String st1=encryptinput();
			System.out.println("\n\tOriginal Text : ");
			System.out.println(st1);
			byte[] dataAfterEnc = encryptString(st1,key,cipher1);
			String stringAfterEnc = new String(dataAfterEnc);
			String encodedStringAfterEnc = Base64.getEncoder().encodeToString(stringAfterEnc.getBytes());
			System.out.println("\n\tEncrypted Text (Base64) : "+encodedStringAfterEnc);
			String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
			System.out.println("\n\tAES Key (Base64) : "+encodedKey);
			byte[] iv = cipher1.getIV();
			String ivString = new String(iv);
			String encodedIV = Base64.getEncoder().encodeToString(ivString.getBytes());
			System.out.println("\n\tIV (Base64) : "+encodedIV);			
			break;
	case 2: String st2=decryptinput();
			byte[] byteArr2 = Base64.getDecoder().decode(st2);
			String stringAfterDec = decryptString(byteArr2,key,cipher1);	
			System.out.println("\n\tDecrypted Text : "+stringAfterDec);
			break;
	case 3: break;
	default: System.out.println("Please enter valid option");
	}
	}while(c!=3);
	}
	catch(Exception e)
	{
		
	}
}
	

	
public static int input()
{
	int a;
	System.out.println("\tData Encryption and Decryption\n\n");
	System.out.println("\n\t****MENU****\n");	
	System.out.println("\t1. Encrypt\n");	
	System.out.println("\t2. Decrypt\n");
	System.out.println("\t3. Exit");
	System.out.println("\tEnter your choice\n");
	Scanner sc=new Scanner(System.in);
	a=sc.nextInt();
	return a;
}

public static String encryptinput()
{
	String st;
	System.out.println("\n\n\tEnter text : ");
	Scanner sc= new Scanner(System.in);
	st=sc.nextLine();
	return st;
}

public static String decryptinput()
{
	String st1;
	System.out.println("\n\n\tEnter encrypted text : ");
	Scanner sc= new Scanner(System.in);
	st1=sc.nextLine();
	return st1;
}

public static SecretKey generateKey(String encryptionType)
{
	try
	{
		KeyGenerator keyGen = KeyGenerator.getInstance(encryptionType);
		SecretKey myKey = keyGen.generateKey();
		return myKey;
	}
	catch(Exception e)
	{
		return null;
	}
}


public static byte[] encryptString(String dataToEnc, SecretKey myKey, Cipher cipher)
{
	try
	{
		byte[] text = dataToEnc.getBytes(UNI);
		cipher.init(Cipher.ENCRYPT_MODE, myKey);
		byte[] encryptedText = cipher.doFinal(text);
		return encryptedText;
	}
	catch (Exception e)
	{
		return null;
	}
}


public static String decryptString(byte[] dataToDec, SecretKey myKey, Cipher cipher)
{
	try
	{
		cipher.init(Cipher.DECRYPT_MODE, myKey);
		byte[] decryptedText = cipher.doFinal(dataToDec);
		String output = new String(decryptedText);
		return output;
	}
	catch(Exception e)
	{
		System.out.println(e);
		return null;
	}
}

}







