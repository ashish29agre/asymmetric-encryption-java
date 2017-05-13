package in.ashish29agre.security;

import in.ashish29agre.security.asymmetric.AsymmetricCryptography;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static in.ashish29agre.security.SecurityConstants.ALGORITHM_RSA;

/* Reference tutorials
*  http://stackoverflow.com/questions/5763723/how-to-fix-the-nosuchalgorithmexception-in-java-when-using-blowfish
*  http://www.macs.hw.ac.uk/~ml355/lore/pkencryption.htm
*/
public class Main {


    public static void main(String[] args) {
        try {
            String currentAlgo = ALGORITHM_RSA;
            AsymmetricCryptography cryptography = new AsymmetricCryptography(currentAlgo);
            cryptography.writeKeys();
            cryptography.readKeys();
            Cipher cipher = Cipher.getInstance(currentAlgo);

            String message = "Hello Ashish!!!";
            cipher.init(Cipher.ENCRYPT_MODE, cryptography.getPrivateKey());
            byte[] encryptedMessageBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            String encryptedMessages = new String(Base64.getEncoder().encode((encryptedMessageBytes)));
            System.out.println(message + " in encrypted form is: " + encryptedMessages);
            cipher.init(Cipher.DECRYPT_MODE, cryptography.getPublicKey());
            byte[] originalMessageBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessages));
            String originalMessage = new String(originalMessageBytes);
            System.out.println("Original message is: " + originalMessage);
        } catch (IOException | NoSuchPaddingException |
                NoSuchAlgorithmException | InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }
}
