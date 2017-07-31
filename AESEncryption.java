import java.io.*;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.spec.KeySpec;

import javax.crypto.SealedObject;

public class AESEncryption {

    /**
     * Returns the secret key generated from the specified password.
     *
     * @param password the password to be used to generate the secret key.
     * @return the secret key generated, with the salt same as the password for convenience.
     * @throws Exception
     */
    public SecretKey getSecretEncryptionKey(String password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), password.getBytes(), 65536, 128);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        return secret;
    }

    /**
     * Returns a randomly generated secret key.
     *
     * @return a randomly generated 128-bit AES secret key.
     * @throws Exception
     */
    public SecretKey getSecretEncryptionKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        SecretKey secKey = generator.generateKey();

        return secKey;
    }

    /**
     * Encrypts an object using the specified secret key.
     *
     * @param data the object to be encrypted.
     * @param secKey the secret key to be used for encryption.
     * @return the encrypted object.
     * @throws Exception
     */
    public SealedObject encrypt(Serializable data, SecretKey secKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secKey);

        SealedObject sealedObject = new SealedObject(data, cipher);

        return sealedObject;
    }

    /**
     * Decrypts an encrypted object using the specified secret key.
     *
     * @param sealedObject the object encrypted to be decrypted.
     * @param secKey the secret key to be used for decryption.
     * @return the decrypted object.
     * @throws Exception
     */
    public Object decrypt(SealedObject sealedObject, SecretKey secKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secKey);

        return sealedObject.getObject(cipher);
    }

}
