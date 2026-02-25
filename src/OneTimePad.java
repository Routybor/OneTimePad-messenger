package src;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.logging.Logger;

public class OneTimePad {
    private static final Logger logger = Logger.getLogger(OneTimePad.class.getName());
    private static final SecureRandom rand = new SecureRandom();

    public static byte[] generateRandomKey(int len) {
        byte[] key = new byte[len];
        rand.nextBytes(key);
        return key;
    }

    public static byte[] xorCipher(byte[] message, byte[] key) {
        byte[] res = new byte[message.length];
        for (int i = 0; i < message.length; i++) {
            res[i] = (byte) (message[i] ^ key[i]);
        }
        return res;
    }

    public static byte[] generateSecretKey(byte[] sharedSecret, int len) {
        try {
            byte[] key = new byte[len];
            int generated = 0;
            int counter = 0;
            byte[] currentState = sharedSecret;

            while (generated < len) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(currentState);
                md.update((byte) counter);
                byte[] digest = md.digest();
                int toCopy = Math.min(digest.length, len - generated);
                System.arraycopy(digest, 0, key, generated, toCopy);
                generated += toCopy;
                currentState = digest;
                counter++;
            }

            return key;
        } catch (Exception e) {
            byte[] fallback = new byte[len];
            rand.nextBytes(fallback);
            return fallback;
        }
    }

    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);
        String message = scan.nextLine();
        byte[] key = generateRandomKey(message.getBytes().length);
        byte[] encrypted = xorCipher(message.getBytes(), key);
        byte[] decrypted = xorCipher(encrypted, key);
        if (logger.isLoggable(java.util.logging.Level.INFO)) {
            logger.info(String.format("Message - { %s }%nEncrypted - { %s }%n Decrypted - { %s }", message,
                    new String(encrypted),
                    new String(decrypted)));
        }
        scan.close();
    }
}