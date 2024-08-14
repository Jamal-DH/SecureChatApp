package sc_project; 

import S1.S1; // Import the server class S1
import C1.C1; // Import the client class C1
import C2.C2; // Import the client class C2
import java.awt.Color; // For setting colors in the GUI
import java.awt.Dimension; // For specifying dimensions of components
import java.awt.FlowLayout; // For setting the layout of the JFrame
import java.awt.Font; // For setting font styles
import java.awt.Toolkit; // For getting screen size and other toolkit functionalities
import java.awt.event.ActionEvent; // For handling button click events
import javax.swing.JButton; // For using buttons in the GUI
import javax.swing.JFrame; // For creating the main window (frame) of the application
import javax.swing.SwingUtilities; // For ensuring thread-safe updates to the GUI

public class SC_Project extends JFrame { // Class extending JFrame to create a GUI window

    private JButton startServersButton; // Declaration of the button to start servers and clients

    // Constructor of SC_Project class
    public SC_Project() {
        initialize(); // Initialize the GUI components
    }

    // Method to initialize GUI components
    private void initialize() {
        setTitle("Main Launcher"); // Set the title of the GUI window
        setSize(600, 460); // Set the size of the window
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); // Set the close operation
        setLocationRelativeTo(null); // Center the window on the screen

        setLayout(new FlowLayout()); // Set the layout manager to FlowLayout

        // Initialize and configure the startServersButton
        startServersButton = new JButton("Start Server and Clients");
        startServersButton.setFocusable(false);
        startServersButton.setBackground(Color.BLACK);
        startServersButton.setForeground(Color.GREEN);
        startServersButton.setFont(new Font("MV Boli", Font.BOLD, 20));
        add(startServersButton); // Add the button to the JFrame

        // Add action listener to the startServersButton to handle click events
        startServersButton.addActionListener((ActionEvent e) -> startServersAndClients());

        setVisible(true); // Make the GUI window visible
    }

    // Method to handle the action of starting servers and clients
    private void startServersAndClients() {
        SwingUtilities.invokeLater(() -> {
            S1 serverFrame = new S1(); // Create an instance of the server
            serverFrame.setLocationRelativeTo(null); // Center the server window on the screen
            serverFrame.setVisible(true); // Make the server window visible
        
            this.dispose(); // Dispose the main launcher window
        });
    }

    // The main method, entry point of the application
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new SC_Project()); // Start the application in a thread-safe way
    }
}
