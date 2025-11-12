package com.sqllib;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import com.sqllib.services.UserService;

@SpringBootTest
@DisplayName("UserService (Vulnerable) Integration Tests")
public class UserServiceTests {

    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    private UserService userService;
    private static boolean initialized = false;

    @BeforeEach
    public void setUp() throws SQLException {
        userService = new UserService();
        
        // Inizializza il database solo una volta
        if (!initialized) {
            initializeDatabase();
            initialized = true;
        }
    }
    
    private void initializeDatabase() throws SQLException {
        try {
            jdbcTemplate.execute("DROP TABLE IF EXISTS users");
            jdbcTemplate.execute("DROP TABLE IF EXISTS sensitive_data");
        } catch (RuntimeException e) {
            // Ignora se la tabella non esiste
        }
        
        jdbcTemplate.execute("CREATE TABLE users (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "username VARCHAR(50) NOT NULL, " +
                "password VARCHAR(50) NOT NULL, " +
                "email VARCHAR(100) NOT NULL)");
        
        jdbcTemplate.execute("CREATE TABLE sensitive_data (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "secret_key VARCHAR(255) NOT NULL, " +
                "credit_card VARCHAR(16) NOT NULL, " +
                "ssn VARCHAR(11) NOT NULL)");
        
        jdbcTemplate.execute("INSERT INTO users (username, password, email) VALUES ('admin', 'secret123', 'admin@example.com')");
        jdbcTemplate.execute("INSERT INTO users (username, password, email) VALUES ('user', 'password', 'user@example.com')");
        jdbcTemplate.execute("INSERT INTO users (username, password, email) VALUES ('test', 'test123', 'test@example.com')");
        
        jdbcTemplate.execute("INSERT INTO sensitive_data (secret_key, credit_card, ssn) " +
                "VALUES ('API_KEY_12345', '4532111122223333', '123-45-6789')");
        jdbcTemplate.execute("INSERT INTO sensitive_data (secret_key, credit_card, ssn) " +
                "VALUES ('SECRET_TOKEN_XYZ', '5555666677778888', '987-65-4321')");
    }

    @Test
    @DisplayName("❌ VULNERABLE: Authentication bypass with SQL comment")
    public void testAuthenticationBypassVulnerable() throws SQLException {
        // Re-inizializza il database per assicurarsi che l'utente admin esista con la password corretta
        try {
            jdbcTemplate.execute("DELETE FROM users WHERE id=1");
            jdbcTemplate.execute("INSERT INTO users (id, username, password, email) VALUES (1, 'admin', 'secret123', 'admin@example.com')");
        } catch (Exception e) {
            // Ignora se esiste già
        }
        
        String username = "admin' --";
        String password = "wrongpassword";
        
        boolean result = userService.authenticate(username, password);
        
        if (result) {
            fail("💥 CRITICAL VULNERABILITY: SQL comment injection bypassed authentication! " +
                 "Attacker logged in with wrong password using payload: " + username);
        }
    }

    @Test
    @DisplayName("❌ VULNERABLE: OR '1'='1' bypass")
    public void testORInjectionVulnerable() throws SQLException {
        String username = "' OR '1'='1";
        String password = "' OR '1'='1";
        
        boolean result = userService.authenticate(username, password);
        
        if (result) {
            fail("💥 CRITICAL VULNERABILITY: OR injection bypassed authentication! " +
                 "Attacker logged in without valid credentials using payload: " + username);
        }
    }

    @Test
    @DisplayName("❌ VULNERABLE: getUserById with injection")
    public void testGetUserByIdVulnerable() throws SQLException {
        String id = "1' OR '1'='1";
        String result = userService.getUserById(id);
        
        // Se l'iniezione funziona, vengono restituiti più utenti invece di uno solo
        // Conta il numero di utenti verificando quante email sono presenti nel risultato
        if (result != null) {
            long userCount = result.chars().filter(ch -> ch == ',').count();
            if (userCount > 1) {
                fail("💥 CRITICAL VULNERABILITY: SQL injection in getUserById exposed ALL users! " +
                     "Payload: " + id + " | Found " + userCount + " users | Result: " + result);
            }
        }
    }

    @Test
    @DisplayName("❌ VULNERABLE: Second Order SQL Injection - Complete Attack Flow")
    public void testSecondOrderInjection() throws SQLException {
        // Questo test dimostra il flusso completo dell'attacco Second Order SQL Injection:
        // Passo 1: Memorizza dati malevoli → Passo 2: Esegue l'iniezione memorizzata
        
        String maliciousUsername = "hackerr'' or 1=1--";
        String password = "password123";
        String email = "hacker@example.com";
        
        try {
            // PASSO 1: Memorizza lo username malevolo nel database
            int userId = userService.createUser(maliciousUsername, password, email);
            
            if (userId <= 0) {
                return; // Creazione utente fallita, test non conclusivo
            }
            
            // PASSO 2: Recupera il profilo utente tramite ID, attivando l'SQL injection memorizzata
            String result = userService.getUserProfile(String.valueOf(userId));
            
            // Se l'iniezione funziona, il risultato conterrà più email (da or 1=1)
            if (result != null && result.contains(",")) {
                fail("💥 CRITICAL VULNERABILITY: Second Order SQL Injection executed! " +
                     "Malicious username '" + maliciousUsername + "' exposed multiple user emails: " + result);
            }
            
        } catch (SQLException e) {
            // Un errore SQL potrebbe indicare che la vulnerabilità esiste
            if (e.getMessage().contains("syntax")) {
                fail("💥 VULNERABILITY: Second Order SQL Injection attempted but failed with syntax error: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("❌ VULNERABLE: Boolean-based Blind SQL Injection")
    public void testBooleanBasedBlindInjection() throws SQLException {
        // Re-inizializza il database per assicurarsi che l'utente admin esista con la password corretta
        try {
            jdbcTemplate.execute("DELETE FROM users WHERE id=1");
            jdbcTemplate.execute("INSERT INTO users (id, username, password, email) VALUES (1, 'admin', 'secret123', 'admin@example.com')");
        } catch (Exception e) {
            // Ignora se esiste già
        }
        
        // L'attaccante estrae la password carattere per carattere
        // Esempio: Verifica se il primo carattere della password di admin è 's'
        String payload = "admin' AND SUBSTRING(password,1,1)='s'--";
        
        boolean exists = userService.checkUserExists(payload);
        
        // Se exists=true, l'iniezione ha funzionato e ha rivelato che la password inizia con 's'
        if (exists) {
            fail("💥 CRITICAL VULNERABILITY: Boolean-based Blind SQL Injection allows password extraction! " +
                 "Payload: " + payload + " | Injection confirmed password starts with 's'");
        }
    }

    @Test
    @DisplayName("❌ VULNERABLE: Time-based Blind SQL Injection with SLEEP()")
    public void testTimeBasedBlindInjection() throws SQLException {
        // Iniezione time-based blind usando la funzione custom SLEEP()
        String payload = "1' AND SLEEP(3)--";
        
        long startTime = System.currentTimeMillis();
        userService.getUserEmail(payload);
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        
        // Se la durata >= 2500ms, SLEEP(3) è stato eseguito, dimostrando la vulnerabilità
        if (duration >= 2500) {
            fail("💥 CRITICAL VULNERABILITY: Time-based Blind SQL Injection executed SLEEP(3)! " +
                 "Payload: " + payload + " | Duration: " + duration + "ms | Allows password extraction via timing attacks");
        }
    }

    @Test
    @DisplayName("❌ VULNERABLE: UNION-based SQL Injection - Extract sensitive data")
    public void testUNIONBasedInjection() throws SQLException {
        // Prima, assicurati che la tabella sensitive_data esista con i dati di test
        try {
            jdbcTemplate.execute("DROP TABLE IF EXISTS sensitive_data");
            jdbcTemplate.execute("CREATE TABLE sensitive_data (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "secret_key VARCHAR(255) NOT NULL, " +
                    "credit_card VARCHAR(16) NOT NULL, " +
                    "ssn VARCHAR(11) NOT NULL)");
            jdbcTemplate.execute("INSERT INTO sensitive_data (secret_key, credit_card, ssn) " +
                    "VALUES ('API_KEY_12345', '4532111122223333', '123-45-6789')");
        } catch (RuntimeException e) {
            // La tabella potrebbe già esistere, continua
        }
        
        // Attacco UNION-based per estrarre numeri di carte di credito
        String payload = "' UNION SELECT credit_card FROM sensitive_data--";
        
        try {
            String result = userService.searchUserByName(payload);
            
            // Se l'iniezione UNION ha funzionato, il risultato contiene numeri di carte di credito
            if (result != null && (result.contains("4532") || result.contains("5555"))) {
                fail("💥 CRITICAL VULNERABILITY: UNION-based SQL Injection exposed credit card data! " +
                     "Payload: " + payload + " | Exposed data: " + result);
            }
        } catch (SQLException e) {
            // Un errore SQL potrebbe indicare che la vulnerabilità esiste
            if (e.getMessage().contains("UNION") || e.getMessage().contains("SELECT")) {
                fail("💥 VULNERABILITY: UNION injection attempted but syntax error occurred: " + e.getMessage());
            }
        }
    }
    
    @Test
    @DisplayName("❌ VULNERABLE: Error-Based SQL Injection - Database error reveals structure")
    public void testErrorBasedInjection() throws SQLException {
        // Attacco error-based: sintassi SQL non valida per generare un errore del database
        String payload = "1'";
        
        String result = userService.getUserPassword(payload);
        
        // Se il messaggio di errore è esposto all'utente, è una vulnerabilità critica
        if (result != null && (result.contains("SQL ERROR") || result.contains("error") || result.contains("ERROR"))) {
            fail("💥 CRITICAL VULNERABILITY: Error-Based SQL Injection exposes database error message! " +
                 "Payload: " + payload + " | Exposed error: " + result);
        }
    }
}
