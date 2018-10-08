import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

public class Main {

    public static final String username = "aspisteam@gmail.com";
    public static final String password = "aspisteam";

    public static final String ct = "miYEmfz0r0vcQ4HiMs7PWz9x16oSH4CwokxpOqE3WyDcNBuBhHp3sCcG0OpoULpcHkEcHIfmjBHkVmmiM3M9AbHwxP9hCX0Q";
    public static final String iv = "mk3i1XlbKY+xiW4qs5SVqQ==";

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        Security.setProperty("crypto.policy", "unlimited");
        //int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        //System.out.println("Max Key Size for AES : " + maxKeySize);


        byte[] ek = pbkdf2_lib.createHash(password, username);
        AES_GCM.decrypt(ct, ek, iv);


        /*int macSize = 125;
        byte[] key = new byte[32];
        byte[] keybyte = "test123".getBytes();
        byte[] inputNouc = "abcdefghijklm".getBytes();
        for (int I = 0; I < keybyte.length; I++) {
            key[I] = keybyte[I];
        }

//      Input data in HEX format
        String input = "ed88fe7b95fa0ffa190b7ab33933fa";
        byte[] inputData= Hex.decode(input);

        BlockCipher engine = new AESEngine();
        CCMParameters params = new CCMParameters(new KeyParameter(key), macSize, inputNouc, null);

        CCMBlockCipher cipher = new CCMBlockCipher(engine);
        cipher.init(true, params);
        byte[] outputText = new byte[cipher.getOutputSize(inputData.length)];
        int outputLen = cipher.processBytes(inputData, 0, inputData.length, outputText , 0);
        cipher.doFinal(outputText, outputLen);

//      outputText and mac are in bytes
        System.out.println(outputText);
        System.out.println(cipher.getMac());*/


       /* String iv_decoded = AES_GCM.Base64_decode(iv);
        final byte[] iv_bytes = iv_decoded.getBytes();

        SecretKey originalKey = new SecretKeySpec(ek, "AES");
//        Object[] encrypt = ccmEncrypt(originalKey, "mydata".getBytes(), iv_bytes);
        Object[] encrypt = ccmDecrypt(originalKey, , ct.getBytes());

        System.out.println(encrypt[0].toString()+ "  | "+encrypt[1].toString());*/


    }

    public static Object[] ccmEncrypt(SecretKey key, byte[] data, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        return new Object[] { cipher.getParameters(), cipher.doFinal(data) };
    }
    public static byte[] ccmDecrypt(SecretKey key, AlgorithmParameters ccmParameters, byte[] cipherText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BCFIPS");
        cipher.init(Cipher.DECRYPT_MODE, key, ccmParameters);
        return cipher.doFinal(cipherText);
    }

}