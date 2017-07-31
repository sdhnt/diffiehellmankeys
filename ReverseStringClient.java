import java.io.*;
import java.net.*;
import java.util.*;
import java.io.Serializable;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SealedObject;

import java.security.PublicKey;


public class ReverseStringClient {

	public static void main(String[] args) throws Exception {
		// Bind the socket to the server with the appropriate port
		Socket socket = new Socket("localhost", 3333);	
		// Setup I/O streams
		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream in = new ObjectInputStream(socket.getInputStream());




		DH alice = new DH();
		PublicKey alicePub = alice.getPubKey();
		PublicKey bobPub = (PublicKey) in.readObject();
		out.writeObject(alicePub);
		out.flush();
 		byte[] aliceShared = alice.getSharedKey(bobPub, 128);
		SecretKey aliceSecret = new SecretKeySpec(aliceShared, "AES");
 		AESEncryption encryptEngine = new AESEncryption();


		System.out.print("Enter the string you want to reverse: ");
		Scanner scan = new Scanner(System.in);
		String s;
		s = scan.nextLine();


		SealedObject cipherObject = encryptEngine.encrypt(s, aliceSecret);
		out.writeObject(cipherObject);
		out.flush();

		SealedObject a= (SealedObject) in.readObject();
		String decryptedText = (String) encryptEngine.decrypt(a, aliceSecret);
		String result = decryptedText;
		
		System.out.println("The result is: " + result);
	}

}
