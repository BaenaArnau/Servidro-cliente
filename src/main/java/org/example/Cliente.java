package org.example;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Scanner;

public class Cliente {
    InetAddress serverIP;
    int serverPort;
    DatagramSocket socket;
    KeyPair keyPair;
    PublicKey serverPublicKey;

    public Cliente() {
        keyPair = Encryp.randomGenerate(1024);
    }

    public void init(String host, int port) throws SocketException, UnknownHostException {
        serverIP = InetAddress.getByName(host);
        serverPort = port;
        socket = new DatagramSocket();
    }

    public void runClient() throws IOException, ClassNotFoundException {
        byte[] receivedData = new byte[1024];

        // Connect to server
        socket.connect(serverIP, serverPort);

        // Sending client's public key to the server
        if (serverPublicKey == null) {
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            ObjectOutputStream objectStream = new ObjectOutputStream(byteStream);
            objectStream.writeObject(keyPair.getPublic());
            byte[] publicKeyBytes = byteStream.toByteArray();

            DatagramPacket publicKeyPacket = new DatagramPacket(publicKeyBytes, publicKeyBytes.length, serverIP, serverPort);
            socket.send(publicKeyPacket);

            System.out.println("Sent client public key to server: " + keyPair.getPublic());
        }

        // Receive server's public key
        DatagramPacket serverPublicKeyPacket = new DatagramPacket(receivedData, receivedData.length);
        socket.receive(serverPublicKeyPacket);

        ByteArrayInputStream byteStream = new ByteArrayInputStream(serverPublicKeyPacket.getData());
        ObjectInputStream objectStream = new ObjectInputStream(byteStream);
        serverPublicKey = (PublicKey) objectStream.readObject();

        System.out.println("Received server public key: " + serverPublicKey);

        Scanner scanner = new Scanner(System.in);

        while (true) {
            // Send message to server
            System.out.print("Client: ");
            String msg = scanner.nextLine();

            // Verificar que el mensaje no sea nulo
            if (msg == null) {
                continue;
            }

            // Verificar que la clave del servidor no sea nula antes de encriptar el mensaje
            if (serverPublicKey != null) {
                byte[] encryptedMsg = Encryp.encryptData(msg.getBytes(), serverPublicKey);
                DatagramPacket packet = new DatagramPacket(encryptedMsg, encryptedMsg.length, serverIP, serverPort);
                socket.send(packet);
            }

            if (msg.equalsIgnoreCase("exit")) {
                break;
            }

            // Receive response from server
            DatagramPacket packet = new DatagramPacket(receivedData, receivedData.length);
            socket.receive(packet);
            byte[] encryptedResponse = packet.getData();
            byte[] decryptedResponse = Encryp.decryptData(encryptedResponse, keyPair.getPrivate());
            String response = new String(decryptedResponse, 0, decryptedResponse.length);
            System.out.println("Server: " + response);

            if (response.equalsIgnoreCase("exit")) {
                break;
            }
        }

        System.out.println("Closing connection...");
        socket.close();
    }

    public static void main(String[] args) {
        Cliente client = new Cliente();
        try {
            client.init("localhost", 5555);
            client.runClient();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}