import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class AES_GCM {

    private static final int GCM_TAG_LENGTH = 64; // in bytes

    public static void decrypt(String ct, byte[] ek, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        //String iv_decoded = Base64_decode(iv);
        //System.out.println(iv_decoded);

        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding");

        //Create Secret Key
        SecretKey originalKey = new SecretKeySpec(ek, "AES");
        System.out.println("SecretKey: "+pbkdf2_lib.toHex(originalKey.getEncoded()));

        // IV decrypt from Base64 and then concert to bytes
        final byte[] iv_bytes = Base64_decode(iv);//iv_decoded.getBytes();
        byte[] iv_final = new byte[13];

        for(int i=0; i<13; i++){
            iv_final[i] = iv_bytes[i];
        }

        System.out.println("IV Length: "+iv_final.length);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv_final);
        cipher.init(Cipher.DECRYPT_MODE, originalKey, spec);
        //byte[] aad2 = "mac".getBytes();;
        //cipher.updateAAD(aad2);

        try {
            byte[] plainText = cipher.doFinal(ct.getBytes());
            System.out.println(new String(plainText));
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            System.out.println(e.toString());
        }
    }

    public static byte[] Base64_decode(String data){
        return Base64.getMimeDecoder().decode(data);
        //return new String(decoded);
    }

}
