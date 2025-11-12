-- SQLite Test Data Initialization
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL
);

INSERT INTO users (id, username, password, email) VALUES (1, 'admin', 'secret123', 'admin@example.com');
INSERT INTO users (id, username, password, email) VALUES (2, 'user', 'password', 'user@example.com');
INSERT INTO users (id, username, password, email) VALUES (3, 'test', 'test123', 'test@example.com');
