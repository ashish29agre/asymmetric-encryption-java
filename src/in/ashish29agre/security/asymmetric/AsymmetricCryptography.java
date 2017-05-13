package in.ashish29agre.security.asymmetric;

import in.ashish29agre.security.SecurityConstants;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by Ashish on 5/13/17.
 */
public class AsymmetricCryptography {

    private AppKeyGenerator mAppKeyGenerator;
    private AppKeyReader mAppKeyReader;
    private String algorithm;

    public AsymmetricCryptography(String algorithm) throws IOException, NoSuchAlgorithmException {
        this.algorithm = algorithm;
        writeKeys();
    }

    public void writeKeys() throws NoSuchAlgorithmException, IOException {
        mAppKeyGenerator = new AppKeyGenerator(SecurityConstants.KEY_LENGTH, algorithm);
        mAppKeyGenerator.createKeys();
        Path keysPath = Paths.get(SecurityConstants.DIR);
        boolean exists = Files.exists(keysPath);
        if (!exists) {
            Files.createDirectory(keysPath);
        }
        Files.write(Paths.get(SecurityConstants.DIR + File.separator + SecurityConstants.PRIVATE_KEY_NAME),
                mAppKeyGenerator.getPrivateKey().getEncoded()
        );
        Files.write(Paths.get(SecurityConstants.DIR + File.separator + SecurityConstants.PUBLIC_KEY_NAME),
                mAppKeyGenerator.getPublicKey().getEncoded()
        );
    }

    public void readKeys() {
        mAppKeyReader = new AppKeyReader(this.algorithm);
        mAppKeyReader.readKeys();
    }

    public PrivateKey getPrivateKey() {
        return this.mAppKeyReader.getPrivateKey();
    }

    public PublicKey getPublicKey() {
        return this.mAppKeyReader.getPublicKey();
    }
}
