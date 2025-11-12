package com.sqllib.config;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import javax.sql.DataSource;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

/**
 * Ensures the database directory exists before any DataSource bean is initialized.
 * This is critical for SQLite file-based databases where the directory must exist
 * before HikariCP attempts to create the connection pool.
 * 
 * This processor intercepts DataSource bean creation and creates the necessary
 * directory structure before the bean is fully initialized.
 */
@Component
public class DataSourceDirectoryInitializer implements BeanPostProcessor {

    private static boolean directoryChecked = false;

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        // Check if this is a DataSource bean and we haven't checked yet
        if (bean instanceof DataSource && !directoryChecked) {
            ensureDataDirectoryExists();
            directoryChecked = true;
        }
        return bean;
    }

    /**
     * Ensures the data directory exists for the SQLite database file.
     * Creates the directory if it doesn't exist.
     * Reads the database path from application.properties.
     */
    private void ensureDataDirectoryExists() {
        try {
            // Load database URL from application.properties
            String dbUrl = loadDatabaseUrl();
            
            // Extract file path from JDBC URL (remove "jdbc:sqlite:" prefix)
            String dbPath = dbUrl.replace("jdbc:sqlite:", "");
            File dbFile = new File(dbPath);
            File parentDir = dbFile.getParentFile();
            
            if (parentDir != null && !parentDir.exists()) {
                if (parentDir.mkdirs()) {
                    System.out.println("✅ Created database directory: " + parentDir.getAbsolutePath());
                } else {
                    System.err.println("⚠️ WARNING: Failed to create database directory: " + parentDir.getAbsolutePath());
                }
            } else if (parentDir != null && parentDir.exists()) {
                System.out.println("✅ Database directory already exists: " + parentDir.getAbsolutePath());
            }
        } catch (Exception e) {
            System.err.println("⚠️ WARNING: Error ensuring data directory exists: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Loads the database URL from application.properties
     */
    private String loadDatabaseUrl() {
        Properties props = new Properties();
        try (InputStream input = getClass().getClassLoader()
                .getResourceAsStream("application.properties")) {
            if (input == null) {
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
}
