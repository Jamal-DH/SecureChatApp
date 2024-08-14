/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package passwordutil;

import org.mindrot.jbcrypt.BCrypt;

public class PasswordUtil {

    // Method to hash a password using bcrypt
    public static String hashPassword(String password) {
        // The strength parameter determines the complexity of the hash (default: 10, you can increase it to make it more secure)
        return BCrypt.hashpw(password, BCrypt.gensalt(12));
    }

    // Method to check a password against a stored hash
    public static boolean checkPassword(String password, String hashedPassword) {
        return BCrypt.checkpw(password, hashedPassword);
    }
}

