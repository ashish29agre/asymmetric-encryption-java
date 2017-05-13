package in.ashish29agre.security.asymmetric;

import in.ashish29agre.security.SecurityConstants;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Ashish on 5/13/17.
 */
final class AppKeyReader {
    private PrivateKey mPrivateKey;
    private PublicKey mPublicKey;
    private String algorithm;

    public AppKeyReader(String algorithm) {
        this.algorithm = algorithm;
    }

    public void readKeys() {
        readPrivateKey();
        readPublicKey();
    }

    private void readPrivateKey() {
        try {
            byte[] privateKeyBytes = Files.readAllBytes(Paths.get(SecurityConstants.DIR + File.separator + SecurityConstants.PRIVATE_KEY_NAME));
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            mPrivateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private void readPublicKey() {
        try {
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get(SecurityConstants.DIR + File.separator + SecurityConstants.PUBLIC_KEY_NAME));
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            mPublicKey = keyFactory.generatePublic(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }


    public PrivateKey getPrivateKey() {
        return mPrivateKey;
    }


    public PublicKey getPublicKey() {
        return mPublicKey;
    }
}
