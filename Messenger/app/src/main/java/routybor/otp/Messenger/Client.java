package routybor.otp.Messenger;

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

    public static void startClient(String serverAddress, int serverPort) {
        try (Scanner scan = new Scanner(System.in)) {
            try (Socket socket = new Socket(serverAddress, serverPort)) {
                InputStream input = socket.getInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(input));
                OutputStream output = socket.getOutputStream();
                PrintWriter writer = new PrintWriter(output, true);
                byte[] shared = difHelHandshake(reader, writer);
                if (shared == null) {
                    return;
                }

                sendLoop(scan, writer, shared);

            } catch (IOException e) {
                logger.severe(e.toString());
            }

        }
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

    public static class Connection {

        private final Socket socket;
        private final PrintWriter writer;
        private final byte[] shared;

        Connection(Socket socket, PrintWriter writer, byte[] shared) {
            this.socket = socket;
            this.writer = writer;
            this.shared = shared;
        }

        public void send(String message) {
            if (socket.isClosed()) {
                return;
            }
            byte[] bytesMessage = message.getBytes(StandardCharsets.UTF_8);
            byte[] key = OneTimePad.generateSecretKey(shared, bytesMessage.length);
            byte[] encryptedMessage = OneTimePad.xorCipher(bytesMessage, key);
            String encryptedB64 = Base64.getEncoder().encodeToString(encryptedMessage);
            writer.println(encryptedB64);
        }

        public void close() {
            try {
                socket.close();
            } catch (IOException e) {
                logger.warning(String.format("Failed to close socket - %s", e.getMessage()));
            }
        }
    }

    public static Connection connectAndListen(String serverAddress, int serverPort, java.util.function.Consumer<String> onMessage, int clientPort) throws IOException {
        Socket socket = new Socket(serverAddress, serverPort);
        InputStream input = socket.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));
        OutputStream output = socket.getOutputStream();
        PrintWriter writer = new PrintWriter(output, true);

        byte[] shared = difHelHandshake(reader, writer);
        if (shared == null || shared.length == 0) {
            socket.close();
            throw new IOException("DH handshake failed");
        }

        byte[] portBytes = ("PORT:" + clientPort).getBytes(StandardCharsets.UTF_8);
        byte[] keyPort = OneTimePad.generateSecretKey(shared, portBytes.length);
        byte[] encryptedPort = OneTimePad.xorCipher(portBytes, keyPort);
        String encryptedB64 = Base64.getEncoder().encodeToString(encryptedPort);
        writer.println(encryptedB64);

        Connection conn = new Connection(socket, writer, shared);

        Thread readerThread = new Thread(() -> {
            try {
                String line;
                java.util.Base64.Decoder decoder = Base64.getDecoder();
                while ((line = reader.readLine()) != null) {
                    try {
                        byte[] encrypted = decoder.decode(line);
                        byte[] key = OneTimePad.generateSecretKey(shared, encrypted.length);
                        byte[] decrypted = OneTimePad.xorCipher(encrypted, key);
                        String msg = new String(decrypted, StandardCharsets.UTF_8);
                        try {
                            onMessage.accept(msg);
                        } catch (Exception ex) {
                            logger.warning(String.format("onMessage callback threw - %s", ex.getMessage()));
                        }
                    } catch (IllegalArgumentException iae) {
                        logger.warning(String.format("Received non-base64 line or decode error - %s", iae.getMessage()));
                    }
                }
            } catch (IOException e) {
                logger.info(String.format("Connection closed - %s", e.getMessage()));
            } finally {
                try {
                    socket.close();
                } catch (IOException ignored) {
                }
            }
        }, "ClientReaderThread-" + serverAddress + ":" + serverPort);

        readerThread.setDaemon(true);
        readerThread.start();

        return conn;
    }
}
