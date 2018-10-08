import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class Old_AES {

    // AES-GCM parameters
    public static final int AES_KEY_SIZE = 256; // in bits
    public static final int GCM_NONCE_LENGTH = 12; // in bytes
    public static final int GCM_TAG_LENGTH = 16; // in bytes

    public static void main(String[] args) throws Exception {

        byte[] input = "Hello AES-GCM World!".getBytes();

        // Initialise random and generate key
        SecureRandom random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE, random);
        SecretKey key = keyGen.generateKey();


        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");

        // OR otherwise as IV
        // IV decrypt from Base64 and then concert to bytes
        final byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce); //nonce = IV

        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce); //2nd is IV
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        //AAD = Tag
        byte[] aad = "Whatever I like".getBytes();;
        cipher.updateAAD(aad);

        byte[] cipherText = cipher.doFinal(input);
        System.out.println("CipherText: "+pbkdf2_lib.toHex(cipherText));


        // Decrypt; nonce is shared implicitly
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        //byte[] aad2 = "Whatever I like ".getBytes();;
        //cipher.updateAAD(aad2);


        try {
            byte[] plainText = cipher.doFinal(cipherText);

            // check if the decryption result matches
            if (Arrays.equals(input, plainText)) {
                System.out.println("Test Passed: match!");
            } else {
                System.out.println("Test Failed: result mismatch!");
                System.out.println(new String(plainText));
            }

        } catch(AEADBadTagException ex) {
            System.out.println("Test Passed: expected ex " + ex);
        }
    }
}
