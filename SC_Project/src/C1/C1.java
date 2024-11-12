package C1; 


import Enc.CryptoUtils; // For encryption and decryption utilities

import javax.swing.*; // For GUI components
import java.awt.*; // For layout and color utilities
import java.awt.event.ActionEvent; // For handling button click events
import java.awt.event.ActionListener;
import java.io.*; // For input/output, particularly for network communication
import java.net.InetAddress; // For getting the IP address of the local host
import java.net.Socket; // For creating a socket for network communication
import java.util.Base64; // For encoding and decoding messages to/from Base64
import java.util.logging.Level; // For logging levels
import java.util.logging.Logger; // For logging purposes
import javax.crypto.SecretKey; // For handling the encryption key

public class C1 extends JFrame { // C1 class extending JFrame to create a GUI window

    // Declaration of GUI components and network communication variables
    private JTextArea textArea;
    private JTextField textField;
    private JButton sendButton;
    private JButton secureChatButton;
    private Socket socket;
    private PrintWriter socketWriter;
    private BufferedReader socketReader;
    private SecretKey secretKey;

    // Constructor of C1 class
    public C1() {
        initialize(); // Initialize GUI components
        setupNetworking(); // Set up network connection
        setupEncryption(); // Set up encryption utilities
    }

    // Method to initialize GUI components
    private void initialize() {
        setTitle("Client 1"); // Set the title of the GUI window
        setSize(500, 800); // Set the size of the window
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); // Set the close operation
        getContentPane().setLayout(new BorderLayout()); // Set the layout manager

        // Initialize and configure text area for displaying messages
        textArea = new JTextArea();
        textArea.setEditable(false); // Make it non-editable
        textArea.setFont(new Font("Consolas", Font.PLAIN, 20)); // Set font
        getContentPane().add(new JScrollPane(textArea), BorderLayout.CENTER); // Add it to the center of the layout

        // Initialize and configure the panel to hold the text field and send button
        JPanel panel = new JPanel();
        getContentPane().add(panel, BorderLayout.SOUTH);
        panel.setLayout(new BorderLayout(0, 0));

        // Initialize and configure text field for inputting messages
        textField = new JTextField();
        textField.setFont(new Font("Consolas", Font.PLAIN, 20));
        panel.add(textField, BorderLayout.CENTER);
        textField.setColumns(10); // Set the number of columns

        // Initialize and configure send button
        sendButton = new JButton("Send");
        sendButton.setFocusable(false);
        sendButton.setBackground(Color.BLACK);
        sendButton.setForeground(Color.GREEN);
        sendButton.setFont(new Font("MV Boli", Font.BOLD, 20));
        panel.add(sendButton, BorderLayout.EAST); // Add it to the east of the panel
       
        // Add action listener to the send button to handle click events
        sendButton.addActionListener((ActionEvent e) -> sendMessage());

        setVisible(true); // Make the GUI window visible
    }




    // Method to set up network connection
    private void setupNetworking() {
        int port = 5000; // Port number for the connection
        try {
            InetAddress host = InetAddress.getLocalHost(); // Get the local host address
            socket = new Socket(host, port); // Create a socket to connect to the server
            socketWriter = new PrintWriter(socket.getOutputStream(), true); // Initialize PrintWriter for sending messages//enable the "auto-flush" feature.
            socketReader = new BufferedReader(new InputStreamReader(socket.getInputStream())); // Initialize BufferedReader for receiving messages

            // Start a new thread to listen for incoming messages
            Thread listenerThread = new Thread(() -> {
                try {
                    String message;
                    while ((message = socketReader.readLine()) != null) { // Continuously read messages
                        // Decrypt the received message and update the GUI
                        String decryptedText = CryptoUtils.decrypt(Base64.getDecoder().decode(message), secretKey);
                        SwingUtilities.invokeLater(() -> textArea.append("Client 2: " + decryptedText + "\n"));
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (Exception ex) {
                    Logger.getLogger(C1.class.getName()).log(Level.SEVERE, null, ex);
                }
            });
            listenerThread.start(); // Start the listener thread
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Method to set up encryption
    private void setupEncryption() {
        try {
            secretKey = CryptoUtils.generateKey(); // Generate the symmetric key for encryption/decryption
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Method to handle sending messages
    private void sendMessage() {
        try {
            String message = textField.getText(); // Get the text from the input field
            byte[] encryptedMessage = CryptoUtils.encrypt(message, secretKey); // Encrypt the message
            socketWriter.println(Base64.getEncoder().encodeToString(encryptedMessage)); // Send the encrypted message as a Base64 encoded string
            textField.setText(""); // Clear the input field
            textArea.append("You: " + message + "\n"); // Append the message to the text area

            // Handle exit commands to close the connection
            if (message.equalsIgnoreCase("exit") || message.equalsIgnoreCase("end")) {
               closeConnection(); // Close the connection if exit/end command is given
//                socket.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Method to close the network connection and exit the application
    public void closeConnection() {
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
            System.exit(0); // Exit the application
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    



}
