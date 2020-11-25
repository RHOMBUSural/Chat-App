package ru.ignashovra.chatapp;


import android.util.Log;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class Secret {

    private static SecretKeySpec key = null;


    public static SecretKeySpec kes() {
        // Set up secret key spec for 128-bit AES encryption and decryption

        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.setSeed("any data used as random seed".getBytes());
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128, sr);
            key = new SecretKeySpec((kg.generateKey()).getEncoded(), "AES");
        } catch (Exception e) {
            Log.e("Crypto", "AES secret key spec error");
        }
        return key;
    }

    public static byte[] getEncode(byte[] bytes) {

        // Encode the original data with AES
        byte[] encodedBytes = null;
        try {
            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.ENCRYPT_MODE, key);
            encodedBytes = c.doFinal(bytes);
        } catch (Exception e) {
            Log.e("Crypto", "AES encryption error");

        }

        return encodedBytes;
    }

    public static byte[ ] getDecode (byte[] bytes ) {
    // Decode the encoded data with AES

              byte[] decodedBytes = null;

            try {
                Cipher c = Cipher.getInstance("AES");
                c.init(Cipher.DECRYPT_MODE, key);
                decodedBytes = c.doFinal(bytes);
            } catch (Exception e) {
                Log.e("Crypto", "AES decryption error");
            }
return decodedBytes;
        }

    }

