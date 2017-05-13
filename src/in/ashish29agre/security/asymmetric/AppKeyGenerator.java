package in.ashish29agre.security.asymmetric;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Created by Ashish on 5/13/17.
 */
final class AppKeyGenerator {
    private KeyPairGenerator mKeyPairGenerator;
    private KeyPair mKeyPair;
    private PrivateKey mPrivateKey;
    private PublicKey mPublicKey;

    public AppKeyGenerator(int keyLength, String algorithm) throws NoSuchAlgorithmException {
        mKeyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        mKeyPairGenerator.initialize(keyLength, new SecureRandom());
    }

    public void createKeys() {
        mKeyPair = mKeyPairGenerator.generateKeyPair();
        mPrivateKey = mKeyPair.getPrivate();
        mPublicKey = mKeyPair.getPublic();
    }

    public PublicKey getPublicKey() {
        return mPublicKey;
    }

    public PrivateKey getPrivateKey() {
        return mPrivateKey;
    }
}
