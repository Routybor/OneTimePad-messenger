package src;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.Logger;

public class Client {
    private static final Logger logger = Logger.getLogger(Client.class.getName());
    private static final SecureRandom rand = new SecureRandom();

    public static void main(String[] args) {
        String serverAddress = "127.0.0.1";
        int serverPort = 5000;
        if (args.length >= 2) {
            try {
                serverAddress = args[0];
                serverPort = Integer.parseInt(args[1]);
            } catch (Exception e) {
                logger.warning("Invalid arguments, using defaults");
            }
        }
        startClient(serverAddress, serverPort);
    }

    public static void startClient(String serverAddress, int serverPort) {
        Scanner scan = new Scanner(System.in);
        try (Socket socket = new Socket(serverAddress, serverPort)) {
            InputStream input = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));
            OutputStream output = socket.getOutputStream();
            PrintWriter writer = new PrintWriter(output, true);
            byte[] shared = difHelHandshake(reader, writer);
            if (shared == null)
                return;

            sendLoop(scan, writer, shared);

        } catch (IOException e) {
            logger.severe(e.toString());
        }
        scan.close();
    }

    private static byte[] difHelHandshake(BufferedReader reader, PrintWriter writer) throws IOException {
        String pLine = reader.readLine();
        String gLine = reader.readLine();
        String aLine = reader.readLine();
        if (pLine == null || gLine == null || aLine == null) {
            logger.severe("Failed to receive DH parameters from server");
            return new byte[0];
        }

        BigInteger p = new BigInteger(pLine);
        BigInteger g = new BigInteger(gLine);
        BigInteger A = new BigInteger(aLine);

        BigInteger b = new BigInteger(2048, rand).mod(p.subtract(BigInteger.TWO)).add(BigInteger.TWO);
        BigInteger B = g.modPow(b, p);

        if (logger.isLoggable(java.util.logging.Level.INFO)) {
            logger.info(String.format("p = %d%n g = %d%n A = %d%n b = %d%n B = %d%n", p, g, A, b, B));
        }

        writer.println(B.toString());

        BigInteger shared = A.modPow(b, p);
        return shared.toByteArray();
    }

    private static void sendLoop(Scanner scan, PrintWriter writer, byte[] shared) {
        boolean running = true;
        while (running && scan.hasNextLine()) {
            String message = scan.nextLine();
            if (message != null) {
                sendMessage(shared, writer, message);
                if (message.equalsIgnoreCase("exit")) {
                    running = false;
                }
            }
        }
    }

    private static void sendMessage(byte[] shared, PrintWriter writer, String message) {
        byte[] bytesMessage = message.getBytes(StandardCharsets.UTF_8);
        byte[] key = OneTimePad.generateSecretKey(shared, bytesMessage.length);
        byte[] encryptedMessage = OneTimePad.xorCipher(bytesMessage, key);
        String encryptedB64 = Base64.getEncoder().encodeToString(encryptedMessage);
        writer.println(encryptedB64);
    }
}