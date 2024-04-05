package org.example;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Arrays;

public class Servidor {
    private DatagramSocket socket;
    private PrivateKey privateKey;

    public Servidor(int port, PrivateKey privateKey) throws SocketException {
        this.socket = new DatagramSocket(port);
        this.privateKey = privateKey;
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

        // Esperar la conexión del cliente
        while (true) {
            // Receive message from client
            DatagramPacket packet = new DatagramPacket(receivedData, receivedData.length);
            socket.receive(packet);
            byte[] encryptedMsg = packet.getData();

            // Decrypt the message using the server's private key
            byte[] decryptedMsg = Encryp.decryptData(encryptedMsg, privateKey);
            String msg = new String(decryptedMsg, 0, decryptedMsg.length);

            System.out.println("Client: " + msg); // Imprimir el mensaje recibido

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
            // Replace null with your private key
            Servidor servidor = new Servidor(5555, null);
            servidor.runServer();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
