package com.sqllib.repositories;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import com.sqllib.utils.DatabaseConnection;

public class UserRepository {
    
    /**
     * VULNERABLE: SQL Injection - String concatenation
     * Example attack: id = "1' OR '1'='1" - returns ALL users
     */
    public String getUserById(String id) throws SQLException {
        String query = "SELECT username FROM users WHERE id = '" + id + "'";
        
        StringBuilder result = new StringBuilder();
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            while (rs.next()) {
                if (result.length() > 0) {
                    result.append(", ");
                }
                result.append(rs.getString("username"));
            }
        }
        return result.length() > 0 ? result.toString() : null;
    }
    
    /**
     * VULNERABLE: SQL Injection in INSERT
     * Returns the ID of the newly created user for Second Order SQL Injection demonstration
     */
    public int createUser(String username, String password, String email) throws SQLException {
        String query = "INSERT INTO users (username, password, email) VALUES ('" + username + "', '" + password + "', '" + email + "')";
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(query);
            
            // Get the last inserted ID
            try (ResultSet rs = stmt.executeQuery("SELECT last_insert_rowid()")) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        }
        return -1;
    }
    
    /**
     * VULNERABLE: Authentication bypass
     */
    public boolean authenticate(String username, String password) throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            return rs.next();
        }
    }
    
    /**
     * VULNERABLE: Second Order SQL Injection - Step 2
     * Retrieves user by ID, then uses stored username in a second vulnerable query
     */
    public String getUserProfile(int userId) throws SQLException {
        // Step 1: Retrieve the stored username using the user ID (safe query)
        String getUserQuery = "SELECT username FROM users WHERE id = " + userId;
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(getUserQuery)) {
            
            if (rs.next()) {
                String storedUsername = rs.getString("username");
                
                // Step 2: Use the stored username in a second query (VULNERABLE!)
                // If the stored username contains SQL injection payload, it will be executed here
                String profileQuery = "SELECT email FROM users WHERE username = '" + storedUsername + "'";
                try (Statement stmt2 = conn.createStatement();
                     ResultSet rs2 = stmt2.executeQuery(profileQuery)) {
                    
                    StringBuilder emails = new StringBuilder();
                    while (rs2.next()) {
                        if (emails.length() > 0) {
                            emails.append(", ");
                        }
                        emails.append(rs2.getString("email"));
                    }
                    return emails.length() > 0 ? emails.toString() : null;
                }
            }
        }
        return null;
    }
    
    /**
     * VULNERABLE: Boolean-based Blind SQL Injection
     * Returns different responses based on query result (true/false)
     * Attacker can extract data bit by bit by observing behavior
     */
    public boolean checkUserExists(String username) throws SQLException {
        // VULNERABLE: Attacker can inject conditions to extract data
        // Example: username = "admin' AND SUBSTRING(password,1,1)='s'--"
        String query = "SELECT COUNT(*) as count FROM users WHERE username = '" + username + "'";
        
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            if (rs.next()) {
                return rs.getInt("count") > 0;
            }
        }
        return false;
    }
    
    /**
     * VULNERABLE: Time-based Blind SQL Injection
     * Returns same response but with time delay if condition is true
     * Attacker extracts data by measuring response time
     */
    public String getUserEmail(String userId) throws SQLException {
        // VULNERABLE: Attacker can inject time delays
        // Example: userId = "1' AND IF(SUBSTRING(password,1,1)='s', SLEEP(5), 0)--"
        String query = "SELECT email FROM users WHERE id = '" + userId + "'";
        
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            if (rs.next()) {
                return rs.getString("email");
            }
        }
        return "User not found";
    }
    
    /**
     * VULNERABLE: UNION-based SQL Injection
     * Allows attacker to extract data from other tables by injecting UNION queries
     * The application expects to return username, but attacker can extract sensitive data
     */
    public String searchUserByName(String username) throws SQLException {
        // VULNERABLE: Attacker can use UNION to query other tables
        // Example: username = "' UNION SELECT credit_card FROM sensitive_data--"
        // This would return credit card numbers instead of usernames
        String query = "SELECT username FROM users WHERE username LIKE '%" + username + "%'";
        
        StringBuilder results = new StringBuilder();
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            while (rs.next()) {
                if (results.length() > 0) {
                    results.append(", ");
                }
                results.append(rs.getString(1)); // Note: using column index (vulnerable to UNION)
            }
        }
        return results.length() > 0 ? results.toString() : "No users found";
    }
    
    /**
     * VULNERABLE: Error-Based SQL Injection
     * Exposes database errors that reveal structure and data
     * Example attack: id = "1 AND 1=CAST((SELECT password FROM users WHERE id=1) AS INT)"
     * 
     * CRITICAL VULNERABILITY: Returns SQL error messages to user!
     * This allows attackers to extract sensitive data through error messages.
     */
    public String getUserPassword(String userId) throws SQLException {
        String query = "SELECT password FROM users WHERE id = " + userId;
        
        try (Connection conn = DatabaseConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            if (rs.next()) {
                return rs.getString("password");
            }
        } catch (SQLException e) {
            // CRITICAL VULNERABILITY: Exposing SQL error to user!
            // This is what makes it "Error-Based SQL Injection"
            // Attacker can see database structure, data types, and even data values
            return "SQL ERROR: " + e.getMessage();
        }
        return null;
    }
}