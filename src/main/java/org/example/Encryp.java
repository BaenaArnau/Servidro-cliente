package org.example;

import javax.crypto.Cipher;
import java.security.*;

public class Encryp {
    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public static byte[] encryptData(byte[] data, PublicKey pub) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA","SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptData(byte[] data, PrivateKey sec) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA","SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, sec);
            decryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return decryptedData;
    }
}