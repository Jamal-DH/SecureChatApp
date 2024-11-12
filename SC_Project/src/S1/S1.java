package S1;

import C1.C1;
import C2.C2;
import passwordutil.PasswordUtil;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.*;

public class S1 extends JFrame {

    // Variable declarations for GUI components and server functionality
    private JTextArea logArea;
    private JButton startButton, stopButton, secureChatButton;
    private ExecutorService pool = Executors.newFixedThreadPool(10);
    private ServerSocket serverSocket1, serverSocket2;
    private static final int PORT1 = 5000;
    private static final int PORT2 = 5001;
    private boolean isRunning = false;
    private ClientHandler client1Handler, client2Handler;
    private String storedHashedPassword;

    // Constructor to initialize the UI
    public S1() {
        UI();
    }

    // Main method to start the application
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new S1());
    }

    // Method to set up the user interface
    private void UI() {

        setTitle("Server S1");
        setSize(700, 800);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 20));
        add(new JScrollPane(logArea), BorderLayout.CENTER);

        startButton = new JButton("Start Server");
        startButton.setFocusable(false);
        startButton.setBackground(Color.BLACK);
        startButton.setForeground(Color.GREEN);
        startButton.setFont(new Font("MV Boli", Font.BOLD, 20));

        secureChatButton = new JButton("Secure Chat");
        secureChatButton.setFocusable(false);
        secureChatButton.setBackground(Color.BLACK);
        secureChatButton.setForeground(Color.GREEN);
        secureChatButton.setFont(new Font("MV Boli", Font.BOLD, 20));

        stopButton = new JButton("Stop Server");
        stopButton.setEnabled(false);
        stopButton.setFocusable(false);
        stopButton.setBackground(Color.BLACK);
        stopButton.setForeground(Color.RED);
        stopButton.setFont(new Font("MV Boli", Font.BOLD, 20));

        JPanel panel = new JPanel();
        panel.add(startButton);
        panel.add(stopButton);
        panel.add(secureChatButton);
        add(panel, BorderLayout.SOUTH);

        startButton.addActionListener(e -> startServer());

        // Action listener for stop button
        stopButton.addActionListener(e -> {
            stopServer();
            System.exit(0);
        });
        this.storedHashedPassword = "$2a$12$Fko3RmJeBO6UJnwsJs8uae66o7kgCZyU2cyqrDZSvVlUaTo0SQNty"; // Hashed password for "jimmie"

        // Create the secure chat button
        secureChatButton.addActionListener(e -> {

            // Create a JLabel with HTML content to customize the font and design
            JLabel messageLabel = new JLabel("<html><body style='font-family:\\\"Lucida Console\\\", monospace;font-size:14px;'>\n"
                    + "<strong>Are you sure you want to stop the server<br>and start the chat application?</strong>\n"
                    + "</body></html>");
            messageLabel.setForeground(Color.BLACK); // Set text color
            messageLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10)); // Add padding

            // Show the confirmation dialog with custom font
            int response = JOptionPane.showConfirmDialog(null,
                    messageLabel,
                    "Confirmation", JOptionPane.YES_NO_OPTION);

            if (response == JOptionPane.YES_OPTION) {
                // Remove all components and add the password panel

                getContentPane().removeAll();
                add(new PasswordPanel(S1.this)); // Pass the parent reference
                revalidate();
                repaint();
            }
        });

        setVisible(true);
    }

    // Method to start the server
    public void startServer() {
        try {
            serverSocket1 = new ServerSocket(PORT1);
            serverSocket2 = new ServerSocket(PORT2);
            isRunning = true;
            updateUIForRunningServer();

            // Executing server logic in a separate thread (pool group of threads)
            pool.execute(() -> {
                try {
                    Socket clientSocket1 = serverSocket1.accept();
                    log("Client1 connected on port " + PORT1);
                    client1Handler = new ClientHandler(clientSocket1, logArea, this, 1);

                    Socket clientSocket2 = serverSocket2.accept();
                    log("Client2 connected on port " + PORT2);
                    client2Handler = new ClientHandler(clientSocket2, logArea, this, 2);

                    pool.execute(client1Handler);
                    pool.execute(client2Handler);

                } catch (IOException e) {
                    log("Server Stopped: " + e.getMessage());
                }
            });

        } catch (IOException e) {
            log("Could not start server: " + e.getMessage());
        }

        // Starting the clients with a delay
        new Thread(() -> {
            try {
                Thread.sleep(5000);
                startClients();
            } catch (InterruptedException ex) {
                ex.printStackTrace();
            }
        }).start();
    }

    // Method to start the client applications
    private void startClients() {
        // Starting client C1
        SwingUtilities.invokeLater(() -> {
            C1 client1Frame = new C1();
            positionFrame(client1Frame, -600);
            client1Frame.setVisible(true);
        });

        // Starting client C2
        SwingUtilities.invokeLater(() -> {
            C2 client2Frame = new C2();
            positionFrame(client2Frame, 600);
            client2Frame.setVisible(true);
        });
    }

    // Method to update the UI when the server is running
    private void updateUIForRunningServer() {
        startButton.setEnabled(false);
        stopButton.setEnabled(true);

        logArea.append("Server is running...\n");
        logArea.append("Listening on ports: " + PORT1 + ", " + PORT2 + "\n");

        try {
            InetAddress ip = InetAddress.getLocalHost();
            logArea.append("Host Name: " + ip.getHostName() + "\n");
            logArea.append("IP Address: " + ip.getHostAddress() + "\n");
        } catch (UnknownHostException e) {
            logArea.append("Unable to determine host name and IP address.\n");
        }
        new Thread(() -> {
            try {
                Thread.sleep(6000);
                int poolSize = ((ThreadPoolExecutor) pool).getPoolSize();
                logArea.append("Thread pool size: " + poolSize + "\n");
            } catch (InterruptedException ex) {
                ex.printStackTrace();
            }
        }).start();

        String dateTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        logArea.append("Server start time: " + dateTime + "\n");
        logArea.append("\n");
    }

    // Method to log messages in the text area
    private void log(String message) {
        SwingUtilities.invokeLater(() -> logArea.append(message + "\n"));
    }

    // Method to stop the server
    private void stopServer() {
        try {
            isRunning = false;

            if (serverSocket1 != null) {
                serverSocket1.close();
            }
            if (serverSocket2 != null) {
                serverSocket2.close();
            }

            if (client1Handler != null) {
                client1Handler.closeConnection();
            }
            if (client2Handler != null) {
                client2Handler.closeConnection();
            }

            pool.shutdownNow();

            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            logArea.append("Server stopped.\n");
        } catch (IOException e) {
            logArea.append("Error stopping server: " + e.getMessage() + "\n");
        }
    }

    // Method to send a message to a specific client (server-side logic) passed on client no.
    public void sendMessageToClient(String message, int clientNumber) {
        if (clientNumber == 1 && client2Handler != null) {
            client2Handler.sendMessage(message);
        } else if (clientNumber == 2 && client1Handler != null) {
            client1Handler.sendMessage(message);
        }
    }

    // Inner class for handling client connections
    private static class ClientHandler implements Runnable {

        private Socket clientSocket;
        private JTextArea logArea;
        private S1 serverInstance; // Accessing Server Methods and Variables
        private int clientNumber;

        // Constructor for client handler
        public ClientHandler(Socket socket, JTextArea logArea, S1 server, int clientNumber) {
            this.clientSocket = socket;
            this.logArea = logArea;
            this.serverInstance = server;
            this.clientNumber = clientNumber;
        }

        // Method to close client connection
        public void closeConnection() {
            try {
                if (clientSocket != null && !clientSocket.isClosed()) {
                    clientSocket.close();
                }
            } catch (IOException e) {
                serverInstance.log("Error closing client socket: " + e.getMessage());
            }
        }

        // Method to send a message to the client
        public void sendMessage(String encryptedMessage) {
            try {
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true); // Enable the "auto-flush" feature.
                out.println(encryptedMessage);
            } catch (IOException e) {
                serverInstance.log("Error sending message: " + e.getMessage());
            }
        }

        // The main run method for the client handler thread
        public void run() {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))) {
                String encryptedInput;
                while ((encryptedInput = in.readLine()) != null) {
                    serverInstance.log("Encrypted message from Client" + clientNumber + ": " + encryptedInput);
                    serverInstance.relayMessage(encryptedInput, this); // The current ClientHandler instance
                }
            } catch (IOException e) {
                serverInstance.log("Error handling client" + clientNumber + ": " + e.getMessage());
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    serverInstance.log("Error closing client" + clientNumber + " socket: " + e.getMessage());
                }
            }
        }
    }

    // Method to relay a message from one client to another (client-to-client communication) used by server
    public void relayMessage(String message, ClientHandler sender) {
        if (sender == client1Handler && client2Handler != null) {
            client2Handler.sendMessage(message);
        } else if (sender == client2Handler && client1Handler != null) {
            client1Handler.sendMessage(message);
        }
    }

    // Method to position the client frames on the screen
    private void positionFrame(JFrame frame, int xOffset) {
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        int x = (screenSize.width - frame.getWidth()) / 2 + xOffset;
        int y = (screenSize.height - frame.getHeight()) / 2;
        frame.setLocation(x, y);
    }

    public class PasswordPanel extends JPanel {

        private int attemptCounter = 0;
        public final S1 parent;
        private JPasswordField passwordField;

        public PasswordPanel(S1 parent) {
            this.parent = parent;

            setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(10, 10, 10, 10);
            this.setBackground(new Color(34, 40, 49));

            // Title Label
            JLabel titleLabel = new JLabel("Secure Access");
            titleLabel.setFont(new Font("Arial", Font.BOLD, 32));
            titleLabel.setForeground(new Color(0, 173, 181));
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.gridwidth = 2;
            gbc.anchor = GridBagConstraints.NORTH;
            gbc.weighty = 0.1;
            add(titleLabel, gbc);

            // Spacer
            gbc.gridy = 1;
            gbc.weighty = 0.2;
            add(Box.createVerticalStrut(20), gbc);

            // Password Label
            JLabel passwordLabel = new JLabel("Enter Password:");
            passwordLabel.setFont(new Font("Arial", Font.PLAIN, 18));
            passwordLabel.setForeground(Color.WHITE);
            gbc.gridx = 0;
            gbc.gridy = 2;
            gbc.gridwidth = 1;
            gbc.anchor = GridBagConstraints.EAST;
            gbc.weighty = 0;
            add(passwordLabel, gbc);

            // Password Field
            passwordField = new JPasswordField(20);
            passwordField.setFont(new Font("Arial", Font.PLAIN, 18));
            passwordField.setForeground(Color.BLACK);
            gbc.gridx = 1;
            gbc.gridy = 2;
            gbc.gridwidth = 1;
            gbc.anchor = GridBagConstraints.WEST;
            add(passwordField, gbc);

            // Spacer
            gbc.gridx = 0;
            gbc.gridy = 3;
            gbc.gridwidth = 2;
            gbc.weighty = 0.5;
            add(Box.createVerticalStrut(10), gbc);


            JButton confirmButton = new JButton("Confirm") {
                @Override
                protected void paintComponent(Graphics g) {
                    if (g instanceof Graphics2D) {
                        Graphics2D g2d = (Graphics2D) g;
                        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                        g2d.setColor(new Color(0, 173, 181));
                        g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 30, 30);
                    }
                    super.paintComponent(g);
                }

                @Override
                public void updateUI() {
                    super.updateUI();
                    setOpaque(false);
                    setForeground(Color.WHITE);
                    setBackground(new Color(0, 173, 181));
                    setFocusPainted(false);
                    setBorder(BorderFactory.createEmptyBorder(15, 40, 15, 40));
                    setFont(new Font("Arial", Font.BOLD, 16));
                }
            };
            confirmButton.setFocusable(false);
            gbc.gridx = 0;
            gbc.gridy = 3;
            gbc.gridwidth = 2;
            gbc.anchor = GridBagConstraints.SOUTH;
            gbc.weighty = 0;
            add(confirmButton, gbc);

            confirmButton.addActionListener(e -> {
                String password = new String(passwordField.getPassword());
                if (parent.checkPassword(password)) {
                    showMessage("Password Correct! Starting Secure chat application.");
                    parent.stopServer();
                    parent.startPythonChatApp();
                } else {
                    attemptCounter++;
                    if (attemptCounter >= 3) {
                        JOptionPane.showMessageDialog(this, "Too many incorrect attempts. Returning to main UI.", "Error", JOptionPane.ERROR_MESSAGE);
                        parent.returnToMainUI();
                        parent.disableSecureChatButton();
                    } else {
                        JOptionPane.showMessageDialog(this, "Incorrect password. Please try again.", "Error", JOptionPane.ERROR_MESSAGE);
                        passwordField.setText("");
                    }
                }
            });
        }

    }

    public void returnToMainUI() {
        getContentPane().removeAll();
        UI();
        revalidate();
        repaint();
    }

    public void disableSecureChatButton() {
        secureChatButton.setEnabled(false);
    }

    private boolean checkPassword(String password) {
        return PasswordUtil.checkPassword(password, storedHashedPassword);
    }

    private void startPythonChatApp() {
        try {
            // Provide the full path to the batch file
            String batchFile = "C:\\Users\\RTX\\Desktop\\twst\\run.bat";

            // Build the command to execute the batch file in a new command prompt window
            ProcessBuilder pb = new ProcessBuilder("cmd", "/c", "start", batchFile);

            // Set the working directory (optional, if needed by the batch file)
            pb.directory(new java.io.File("C:\\Users\\RTX\\Desktop\\twst"));

            // Set environment variables (if any are needed)
            Map<String, String> env = pb.environment();
            // env.put("ENV_VAR_NAME", "value"); // Uncomment and set as needed

            // Start the batch file
            pb.start();

            // Exit the Java application immediately
            System.exit(0);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public void showMessage(String message) {
        Frame parentFrame = (Frame) SwingUtilities.getWindowAncestor(this);
        JDialog dialog = new JDialog(parentFrame, "Success", true);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        dialog.setSize(600, 400);
        dialog.setLayout(new BorderLayout());

        // Create and style the panel
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(new Color(34, 40, 49));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);

        // Create and style the label
        JLabel label = new JLabel("<html><body style='text-align: center; color: white;'>"
                + message.replace("Secure chat application",
                        "<span style='font-weight: bold; color: #00AD65;'>Secure chat application</span>")
                + "</body></html>");
        label.setFont(new Font("Arial", Font.PLAIN, 18));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.CENTER;
        panel.add(label, gbc);

        // Create and style the OK button
        JButton okButton = new JButton("OK") {
            @Override
            protected void paintComponent(Graphics g) {
                if (g instanceof Graphics2D) {
                    Graphics2D g2d = (Graphics2D) g;
                    g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    g2d.setColor(new Color(0, 173, 181));
                    g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 30, 30);
                }
                super.paintComponent(g);
            }

            @Override
            public void updateUI() {
                super.updateUI();
                setOpaque(false);
                setForeground(Color.WHITE);
                setBackground(new Color(0, 173, 181));
                setFocusPainted(false);
                setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
                setFont(new Font("Arial", Font.BOLD, 16));
            }
        };
        okButton.setFocusable(false);
        gbc.gridy = 1;
        panel.add(okButton, gbc);

        okButton.addActionListener(e -> dialog.dispose());

        dialog.add(panel, BorderLayout.CENTER);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }
}
