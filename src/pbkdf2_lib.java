import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/*
* EK e891bad84b8cdb0514472df55832746f9191b7e4366f9ced2e1dadd6d4a96ebe
* Username : aspisteam@gmail.com
* Password : aspisteam
* */


public class pbkdf2_lib {

    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    // The following constants may be changed without breaking existing hashes.
    private static final int HASH_BYTES = 32;
    private static final int PBKDF2_ITERATIONS = 1000;

    public static byte[] createHash(String password, String username) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = username.getBytes();
        return pbkdf2(password.toCharArray(), salt, PBKDF2_ITERATIONS, HASH_BYTES);
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        return skf.generateSecret(spec).getEncoded();
    }

    public static String toHex(byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
            return String.format("%0" + paddingLength + "d", 0) + hex;
        else
            return hex;
    }

}
