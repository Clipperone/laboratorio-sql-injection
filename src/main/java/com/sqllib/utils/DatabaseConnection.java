package com.sqllib.utils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

import org.sqlite.Function;

public class DatabaseConnection {
    // SQLite database URL - loaded from application.properties
    // This centralizes configuration and ensures consistency
    private static final String URL = loadDatabaseUrl();
    
    /**
     * Loads the database URL from application.properties
     * This ensures both Spring Boot (HikariCP) and direct JDBC connections use the same database
     */
    private static String loadDatabaseUrl() {
        Properties props = new Properties();
        try (InputStream input = DatabaseConnection.class.getClassLoader()
                .getResourceAsStream("application.properties")) {
            if (input == null) {
                // Fallback to default if application.properties not found
                System.err.println("WARNING: application.properties not found, using default database URL");
                return "jdbc:sqlite:data/sqllib.db";
            }
            props.load(input);
            String url = props.getProperty("spring.datasource.url");
            if (url == null || url.isEmpty()) {
                System.err.println("WARNING: spring.datasource.url not found in application.properties, using default");
                return "jdbc:sqlite:data/sqllib.db";
            }
            return url;
        } catch (IOException e) {
            System.err.println("ERROR loading application.properties: " + e.getMessage());
            return "jdbc:sqlite:data/sqllib.db"; // Fallback
        }
    }
    
    /**
     * Ensures the data directory exists for the SQLite database file.
     * Creates the directory if it doesn't exist.
     * Extracts the directory path from the JDBC URL (e.g., "jdbc:sqlite:data/sqllib.db" -> "data")
     */
    private static void ensureDataDirectoryExists() {
        try {
            // Extract file path from JDBC URL (remove "jdbc:sqlite:" prefix)
            String dbPath = URL.replace("jdbc:sqlite:", "");
            File dbFile = new File(dbPath);
            File parentDir = dbFile.getParentFile();
            
            if (parentDir != null && !parentDir.exists()) {
                if (parentDir.mkdirs()) {
                    System.out.println("✅ Created database directory: " + parentDir.getAbsolutePath());
                } else {
                    System.err.println("⚠️ WARNING: Failed to create database directory: " + parentDir.getAbsolutePath());
                }
            }
        } catch (Exception e) {
            System.err.println("⚠️ WARNING: Error ensuring data directory exists: " + e.getMessage());
            // Don't throw exception - let SQLite try to create the file anyway
        }
    }
    
    public static Connection getConnection() throws SQLException {
        // Create data directory if it doesn't exist
        ensureDataDirectoryExists();
        
        Properties properties = new Properties();
        // Enable foreign keys for SQLite
        properties.setProperty("foreign_keys", "ON");
        
        Connection conn = DriverManager.getConnection(URL, properties);
                
        // Additional PRAGMA settings
        conn.createStatement().execute("PRAGMA synchronous = OFF");
        
        // Register custom SLEEP() function for time-based SQL injection attacks
        registerSleepFunction(conn);
        
        return conn;
    }
    
    /**
     * Registers a custom SLEEP(seconds) function in SQLite.
     * This mimics MySQL's SLEEP() for time-based blind SQL injection demonstrations.
     * 
     * Usage: SELECT * FROM users WHERE id=1 AND SLEEP(5)
     * 
     * @param conn SQLite connection
     * @throws SQLException if registration fails
     */
    private static void registerSleepFunction(Connection conn) throws SQLException {
        Function.create(conn, "SLEEP", new Function() {
            @Override
            protected void xFunc() throws SQLException {
                // Get sleep duration in seconds from first argument
                int seconds = value_int(0);
                
                try {
                    // Sleep for specified duration (in milliseconds)
                    Thread.sleep(seconds * 1000L);
                } catch (InterruptedException e) {
                    // Restore interrupt status
                    Thread.currentThread().interrupt();
                }
                
                // Return 0 (success) like MySQL SLEEP()
                result(0);
            }
        });
    }
}