import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This class manages Diffie-Hellman keys for a user.
 */
public class DH {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    /**
     * Initializes a newly created <code>DH</code> objects with private and public keys generated.
     *
     * @throws Exception
     */
    public DH() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    /**
     * Returns the public key.
     *
     * @return the public key managed by this instance.
     */
    public PublicKey getPubKey() {
        return publicKey;
    }

    /**
     * Generates the shared secret using the user's private key and the supplied public key.
     *
     * @param pubKey the <code>DH</code> public key of the other party.
     * @param keySize the size of the shared secret in bits.
     * @return the shared secret generated.
     * @throws Exception
     */
    public byte[] getSharedKey(PublicKey pubKey, int keySize) throws Exception {
        KeyAgreement keyEngine = KeyAgreement.getInstance("DH");
        keyEngine.init(privateKey);
        keyEngine.doPhase(pubKey, true);

        byte[] sharedKey = keyEngine.generateSecret();
        int numBytes = keySize / 8;
        byte[] requiredKey = new byte[numBytes];
        System.arraycopy(sharedKey, 0, requiredKey, 0, numBytes);

        return requiredKey;
    }

}
