package org.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Servidor {
    private DatagramSocket socket;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public Servidor(int port, PrivateKey privateKey, PublicKey publicKey) throws SocketException {
        this.socket = new DatagramSocket(port);
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public void runServer() throws IOException, ClassNotFoundException {
        byte[] receivedData = new byte[4096]; // Aumentar el tamaño del búfer

        // Receive client's public key
        DatagramPacket publicKeyPacket = new DatagramPacket(receivedData, receivedData.length);
        socket.receive(publicKeyPacket);

        // Process the public key (assuming it's sent as an object)
        ByteArrayInputStream byteStream = new ByteArrayInputStream(publicKeyPacket.getData());
        ObjectInputStream objectStream = new ObjectInputStream(byteStream);
        PublicKey clientPublicKey = (PublicKey) objectStream.readObject();

        System.out.println("Received public key from client: " + clientPublicKey);

        // Send server's public key to client
        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteOutputStream);
        objectOutputStream.writeObject(publicKey);
        byte[] publicKeyBytes = byteOutputStream.toByteArray();

        DatagramPacket serverPublicKeyPacket = new DatagramPacket(publicKeyBytes, publicKeyBytes.length,
                publicKeyPacket.getAddress(), publicKeyPacket.getPort());
        socket.send(serverPublicKeyPacket);

        // Receive and process messages from client
        while (true) {
            DatagramPacket packet = new DatagramPacket(receivedData, receivedData.length);
            socket.receive(packet);
            byte[] encryptedMsg = packet.getData();

            // Decrypt the message using the client's public key
            byte[] decryptedMsg = Encryp.decryptData(encryptedMsg, privateKey);
            String msg = new String(decryptedMsg, 0, decryptedMsg.length);

            System.out.println("Client: " + msg);

            if (msg.equalsIgnoreCase("exit")) {
                break;
            }

            // Echo the message back to the client
            String response = "Server received: " + msg;
            byte[] encryptedResponse = Encryp.encryptData(response.getBytes(), clientPublicKey);
            DatagramPacket responsePacket = new DatagramPacket(encryptedResponse, encryptedResponse.length,
                    packet.getAddress(), packet.getPort());
            socket.send(responsePacket);
        }

        socket.close();
    }

    public static void main(String[] args) {
        try {
            // Generate server's key pair
            KeyPair serverKeyPair = Encryp.randomGenerate(1024);
            PublicKey serverPublicKey = serverKeyPair.getPublic();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();

            // Replace null with server's private key and public key
            Servidor servidor = new Servidor(5555, serverPrivateKey, serverPublicKey);
            servidor.runServer();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
