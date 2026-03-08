package routybor.otp.Messenger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Logger;

public class Server {

    private static final Logger logger = Logger.getLogger(Server.class.getName());
    private static final SecureRandom rand = new SecureRandom();
    private static ServerSocket currentServerSocket;

    public static void startServer(String ip, int port, MessengerFrame frame) {
        try (ServerSocket serverSocket = new ServerSocket(port, 50, InetAddress.getByName(ip))) {
            currentServerSocket = serverSocket;
            boolean keepRunning = true;
            while (keepRunning && !serverSocket.isClosed()) {
                logger.info(String.format("Waiting for connection on %s:%d", ip, port));
                Socket socket = serverSocket.accept();
                if (logger.isLoggable(java.util.logging.Level.INFO)) {
                    logger.info(String.format("Client connected - %s%n", socket.getRemoteSocketAddress()));
                }
                keepRunning = handleClient(socket, frame);
            }
        } catch (IOException e) {
            logger.severe(e.getMessage());
        } finally {
            currentServerSocket = null;
        }
    }

    public static void stopServer() {
        if (currentServerSocket != null && !currentServerSocket.isClosed()) {
            try {
                currentServerSocket.close();
            } catch (IOException e) {
                logger.warning(String.format("Failed to close server socket - %s", e.getMessage()));
            }
        }
    }

    private static boolean handleClient(Socket socket, MessengerFrame frame) {
        try {
            InputStream input = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));
            OutputStream out = socket.getOutputStream();
            PrintWriter writer = new PrintWriter(out, true);
            String ip = socket.getRemoteSocketAddress().toString().split(":")[0].replace("/", "");
            byte[] shared = difHelHandshake(reader, writer);
            if (shared == null || shared.length == 0) {
                closeResources(reader, writer, socket);
                return false;
            }

            boolean keepRunning = receiveLoop(reader, shared, ip, frame);

            closeResources(reader, writer, socket);
            return keepRunning;
        } catch (IOException e) {
            logger.warning(e.getMessage());
            closeSocket(socket);
            return false;
        }
    }

    private static boolean processMessage(String encryptedB64, byte[] shared, String ip, MessengerFrame frame) {
        try {
            byte[] encryptedMessage = Base64.getDecoder().decode(encryptedB64);
            byte[] key = OneTimePad.generateSecretKey(shared, encryptedMessage.length);
            byte[] decrypted = OneTimePad.xorCipher(encryptedMessage, key);
            String message = new String(decrypted, StandardCharsets.UTF_8);
            if (logger.isLoggable(java.util.logging.Level.INFO)) {
                logger.info(String.format("Received message { %s } from { %s }", message, ip));
            }
            frame.onMessageReceived(message, ip);
            if ("exit".equalsIgnoreCase(message.trim())) {
                logger.info("Shutting down server...");
                return false;
            }
        } catch (IllegalArgumentException iae) {
            logger.warning(iae.getMessage());
        }
        return true;
    }

    private static byte[] difHelHandshake(BufferedReader reader, PrintWriter writer) throws IOException {
        BigInteger p = BigInteger.probablePrime(2048, rand);
        BigInteger g = BigInteger.valueOf(5);

        BigInteger a = new BigInteger(2048, rand).mod(p.subtract(BigInteger.TWO)).add(BigInteger.TWO);
        BigInteger A = g.modPow(a, p);

        writer.println(p.toString());
        writer.println(g.toString());
        writer.println(A.toString());

        String clientPubLine = reader.readLine();
        if (clientPubLine == null) {
            logger.warning("Client closed before sending public value");
            return new byte[0];
        }
        BigInteger B = new BigInteger(clientPubLine);

        BigInteger shared = B.modPow(a, p);
        return shared.toByteArray();
    }

    private static boolean receiveLoop(BufferedReader reader, byte[] shared, String ip, MessengerFrame frame) throws IOException {
        String portLine = reader.readLine();
        if (portLine != null) {
            try {
                byte[] encrypted = Base64.getDecoder().decode(portLine);
                byte[] key = OneTimePad.generateSecretKey(shared, encrypted.length);
                byte[] decrypted = OneTimePad.xorCipher(encrypted, key);
                String portMsg = new String(decrypted, StandardCharsets.UTF_8);
                if (portMsg.startsWith("PORT:")) {
                    int clientPort = Integer.parseInt(portMsg.substring(5));
                    frame.onClientConnected(ip, clientPort);
                }
            } catch (NumberFormatException e) {
                logger.warning(String.format("Failed to parse port message - %s", e.getMessage()));
            }
        }

        String encryptedB64;
        while ((encryptedB64 = reader.readLine()) != null) {
            boolean keepRunning = processMessage(encryptedB64, shared, ip, frame);
            if (!keepRunning) {
                return false;
            }
        }
        if (logger.isLoggable(java.util.logging.Level.INFO)) {
            logger.info(String.format("Client disconnected - %s. Shutting down server.", ip));
        }
        return false;
    }

    private static void closeResources(BufferedReader reader, PrintWriter writer, Socket socket) {
        try (writer) {
            try {
                reader.close();
            } catch (IOException ignore) {
                // doesn't matter
            }
        }
        closeSocket(socket);
    }

    private static void closeSocket(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignore) {
            // doesn't matter
        }
    }
}
