import java.io.*;
import java.net.*;
import java.io.Serializable;
import java.security.PublicKey;


import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SealedObject;
public class ReverseStringServer {

	// Returns a String that is the reverse of the parameter s
	public static String reverse(String s) {
		String result = "";
		int length = s.length();

		for (int i = length - 1; i >= 0; i--) {
			result = result + s.charAt(i);
		}

		return result;
	}

	public static void main(String[] args) throws Exception {
		// Create server socket listening on port
		int port = 3333;
		ServerSocket serverSocket = new ServerSocket(port);
	
      
		// Declare client socket
		Socket clientSocket;

		while (true) { // Provide service continuously
			clientSocket = serverSocket.accept();

			ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
			ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());

        DH bob = new DH();
        PublicKey bobPub = bob.getPubKey();
	    out.writeObject(bobPub);
	    out.flush();
        PublicKey alicePub = (PublicKey) in.readObject();



		byte[] bobShared = bob.getSharedKey(alicePub, 128);
        SecretKey bobSecret = new SecretKeySpec(bobShared, "AES");
        AESEncryption encryptEngine = new AESEncryption();


			
			SealedObject a = (SealedObject) in.readObject();
			String decryptedText = (String) encryptEngine.decrypt(a, bobSecret);
			String s = decryptedText;
			System.out.println(s);
			String result = reverse(s);
			System.out.println(result);
			
			SealedObject cipherObject = encryptEngine.encrypt(result, bobSecret);
			out.writeObject(cipherObject);
			out.flush();
			
			out.close();
			in.close();
			clientSocket.close();
		}
	}

}
