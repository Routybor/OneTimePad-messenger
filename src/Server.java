package src;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Logger;

public class Server {
    private static final Logger logger = Logger.getLogger(Server.class.getName());
    private static int port = 5000;
    private static SecureRandom rand = new SecureRandom();

    public static void main(String[] args) {
        startServer(port);
    }

    public static void startServer(int port) {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            boolean keepRunning = true;
            while (keepRunning && !serverSocket.isClosed()) {
                logger.info("Waiting for connection...");
                Socket socket = serverSocket.accept();
                logger.info("Client connected - " + socket.getRemoteSocketAddress());
                keepRunning = handleClient(socket);
            }
        } catch (IOException e) {
            logger.severe(e.getMessage());
        }
    }

    private static boolean handleClient(Socket socket) {
        try {
            InputStream input = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));
            OutputStream out = socket.getOutputStream();
            PrintWriter writer = new PrintWriter(out, true);
            byte[] shared = difHelHandshake(reader, writer);
            if (shared == null || shared.length == 0) {
                closeResources(reader, writer, socket);
                return false;
            }

            boolean keepRunning = receiveLoop(reader, shared, socket);

            closeResources(reader, writer, socket);
            return keepRunning;
        } catch (IOException e) {
            logger.warning(e.getMessage());
            closeSocket(socket);
            return false;
        }
    }

    private static boolean processMessage(String encryptedB64, byte[] shared, String ip) {
        try {
            byte[] encryptedMessage = Base64.getDecoder().decode(encryptedB64);
            byte[] key = OneTimePad.generateSecretKey(shared, encryptedMessage.length);
            byte[] decrypted = OneTimePad.xorCipher(encryptedMessage, key);
            String message = new String(decrypted, StandardCharsets.UTF_8);
            if (logger.isLoggable(java.util.logging.Level.INFO)) {
                logger.info(String.format("Received message { %s } from { %s }", message, ip));
            }
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

        if (logger.isLoggable(java.util.logging.Level.INFO)) {
            logger.info(String.format("p = %d%n g = %d%n a = %d%n A = %d%n", p, g, a, A));
        }

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

    private static boolean receiveLoop(BufferedReader reader, byte[] shared, Socket socket) throws IOException {
        String encryptedB64;
        String ip = socket.getRemoteSocketAddress().toString();
        while ((encryptedB64 = reader.readLine()) != null) {
            boolean keepRunning = processMessage(encryptedB64, shared, ip);
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
        try {
            reader.close();
        } catch (IOException ignore) {
            // doesn't matter
        }
        writer.close();
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
