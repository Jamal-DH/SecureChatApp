package Enc; 

import javax.crypto.Cipher; // Importing the Cipher class for encryption and decryption
import javax.crypto.KeyGenerator; // Importing KeyGenerator for generating the encryption key
import javax.crypto.SecretKey; // Importing SecretKey to represent the encryption key
import javax.crypto.spec.SecretKeySpec; // Importing SecretKeySpec for specifying a SecretKey in a provider-independent way

// Definition of the CryptoUtils class
public class CryptoUtils {
    private static final String ALGORITHM = "AES"; // Constant to specify the use of the AES algorithm
    private static final int KEY_SIZE = 128; // Constant to set the key size to 128 bits. AES also supports 192 or 256 bits

    // Method to generate a SecretKey for AES encryption
    public static SecretKey generateKey() throws Exception {
        // Hardcoded byte array to create a key. 
        byte[] keyBytes = new byte[] { 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        return new SecretKeySpec(keyBytes, "AES"); // Creating a new SecretKeySpec for AES encryption with the given key
    }

    // Method to encrypt a String using the provided SecretKey
    public static byte[] encrypt(String input, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM); // Getting an instance of the Cipher for AES
        cipher.init(Cipher.ENCRYPT_MODE, key); // Initializing the cipher in encryption mode with the given key
        return cipher.doFinal(input.getBytes()); // Encrypting the input string and returning the encrypted byte array
    }

    // Method to decrypt a byte array using the provided SecretKey
    public static String decrypt(byte[] input, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM); // Getting an instance of the Cipher for AES
        cipher.init(Cipher.DECRYPT_MODE, key); // Initializing the cipher in decryption mode with the given key
        byte[] decrypted = cipher.doFinal(input); // Decrypting the input byte array
        return new String(decrypted); // Converting the decrypted byte array back to a String and returning it
    }
}
