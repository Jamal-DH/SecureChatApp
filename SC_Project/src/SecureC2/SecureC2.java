/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SecureC2;

import Enc.CryptoUtils;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.Socket;
import java.util.Base64;
import javax.crypto.SecretKey;

public class SecureC2 extends JFrame {

    private JTextArea textArea;
    private JTextField textField;
    private JButton sendButton;
    private Socket socket;
    private PrintWriter socketWriter;
    private BufferedReader socketReader;
    private SecretKey secretKey;

    public SecureC2(String ip, int port, String password) {
        initialize();
        setupNetworking(ip, port, password);
        setupEncryption();
    }

    private void initialize() {
        setTitle("Secure Client 2");
        setSize(500, 800);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        getContentPane().setLayout(new BorderLayout());

        textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setFont(new Font("Consolas", Font.PLAIN, 20));
        getContentPane().add(new JScrollPane(textArea), BorderLayout.CENTER);

        JPanel panel = new JPanel();
        getContentPane().add(panel, BorderLayout.SOUTH);
        panel.setLayout(new BorderLayout(0, 0));

        textField = new JTextField();
        textField.setFont(new Font("Consolas", Font.PLAIN, 20));
        panel.add(textField, BorderLayout.CENTER);
        textField.setColumns(10);

        sendButton = new JButton("Send");
        sendButton.setFocusable(false);
        sendButton.setBackground(Color.BLACK);
        sendButton.setForeground(Color.GREEN);
        sendButton.setFont(new Font("MV Boli", Font.BOLD, 20));
        panel.add(sendButton, BorderLayout.EAST);
        sendButton.addActionListener((ActionEvent e) -> sendMessage());

        setVisible(true);
    }

    private void setupNetworking(String ip, int port, String password) {
        try {
            socket = new Socket(ip, port);
            socketWriter = new PrintWriter(socket.getOutputStream(), true);
            socketReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            Thread listenerThread = new Thread(() -> {
                try {
                    String message;
                    while ((message = socketReader.readLine()) != null) {
                        String decryptedText = CryptoUtils.decrypt(Base64.getDecoder().decode(message), secretKey);
                        SwingUtilities.invokeLater(() -> textArea.append("Client 1: " + decryptedText + "\n"));
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            });
            listenerThread.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void setupEncryption() {
        try {
            secretKey = CryptoUtils.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void sendMessage() {
        try {
            String message = textField.getText();
            byte[] encryptedMessage = CryptoUtils.encrypt(message, secretKey);
            socketWriter.println(Base64.getEncoder().encodeToString(encryptedMessage));
            textField.setText("");
            textArea.append("You: " + message + "\n");

            if (message.equalsIgnoreCase("exit") || message.equalsIgnoreCase("end")) {
                closeConnection();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void closeConnection() {
        try {
            if (socketWriter != null) {
                socketWriter.close();
            }
            if (socketReader != null) {
                socketReader.close();
            }
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
            System.exit(0);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
