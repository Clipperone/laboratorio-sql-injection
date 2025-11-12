-- SQLite Database Schema - Clean initialization on every startup

-- Drop existing tables to ensure clean state
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS sensitive_data;

-- Create users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL
);

-- Create sensitive data table (for UNION-based injection demonstration)
CREATE TABLE sensitive_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_key VARCHAR(255) NOT NULL,
    credit_card VARCHAR(16) NOT NULL,
    ssn VARCHAR(11) NOT NULL
);

-- Insert initial test data
INSERT INTO users (username, password, email) VALUES ('admin', 'secret123', 'admin@example.com');
INSERT INTO users (username, password, email) VALUES ('user', 'password', 'user@example.com');
INSERT INTO users (username, password, email) VALUES ('test', 'test123', 'test@example.com');

INSERT INTO sensitive_data (secret_key, credit_card, ssn) VALUES ('API_KEY_12345', '4532111122223333', '123-45-6789');
INSERT INTO sensitive_data (secret_key, credit_card, ssn) VALUES ('SECRET_TOKEN_XYZ', '5555666677778888', '987-65-4321');