package com.sqllib.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.sqllib.services.UserService;

/**
 * Controller Web UI per Laboratorio SQL Injection
 * Gestisce tutte le pagine web e le interazioni utente tramite interfaccia browser
 */
@Controller
public class WebViewController {

    @Autowired
    private UserService userService;

    /**
     * Dashboard - Pagina principale
     */
    @GetMapping("/")
    public String dashboard(Model model) {
        model.addAttribute("pageTitle", "Laboratorio SQL Injection - Dashboard");
        return "dashboard";
    }

    /**
     * Pagina di Test Bypass Autenticazione
     */
    @GetMapping("/auth-bypass")
    public String authBypass(Model model) {
        model.addAttribute("pageTitle", "Bypass Autenticazione SQL Injection");
        model.addAttribute("attackType", "Bypass Autenticazione");
        model.addAttribute("description", "Testa commenti SQL (--) e injection OR per bypassare il login");
        return "auth-bypass";
    }

    /**
     * Elabora Bypass Autenticazione - Vulnerabile
     */
    @PostMapping("/auth-bypass/vulnerable")
    @ResponseBody
    public AttackResult authBypassVulnerable(@RequestParam String username, @RequestParam String password) {
        try {
            long startTime = System.currentTimeMillis();
            boolean result = userService.authenticate(username, password);
            long duration = System.currentTimeMillis() - startTime;
            
            // Ottiene i dati utente reali per mostrare cosa è stato estratto
            String userData = result ? "✅ Autenticazione riuscita - Accesso consentito!" : "❌ Autenticazione fallita";
            
            return new AttackResult(
                result,
                result ? "🚨 VULNERABILE! Autenticazione bypassata!" : "✅ Autenticazione fallita (come previsto)",
                "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'",
                duration,
                result ? "CRITICAL" : "SAFE",
                userData
            );
        } catch (Exception e) {
            return new AttackResult(false, "❌ Errore: " + e.getMessage(), "", 0, "ERROR");
        }
    }

    /**
     * Pagina di Test Recupero Utente
     */
    @GetMapping("/user-retrieval")
    public String userRetrieval(Model model) {
        model.addAttribute("pageTitle", "Recupero Dati Utente SQL Injection");
        model.addAttribute("attackType", "Injection SELECT");
        model.addAttribute("description", "Testa injection OR per recuperare utenti multipli");
        return "user-retrieval";
    }

    /**
     * Elabora Recupero Utente - Vulnerabile
     */
    @PostMapping("/user-retrieval/vulnerable")
    @ResponseBody
    public AttackResult userRetrievalVulnerable(@RequestParam String userId) {
        try {
            long startTime = System.currentTimeMillis();
            String result = userService.getUserById(userId);
            long duration = System.currentTimeMillis() - startTime;
            
            boolean isVulnerable = result != null && result.contains(",");
            
            return new AttackResult(
                isVulnerable,
                isVulnerable ? "🚨 VULNERABILE! Utenti multipli esposti: " + result : "✅ Singolo utente restituito",
                "SELECT username FROM users WHERE id='" + userId + "'",
                duration,
                isVulnerable ? "CRITICAL" : "SAFE",
                result
            );
        } catch (Exception e) {
            return new AttackResult(false, "❌ Errore: " + e.getMessage(), "", 0, "ERROR");
        }
    }

    /**
     * Pagina di Test Injection UNION-Based
     */
    @GetMapping("/union-injection")
    public String unionInjection(Model model) {
        model.addAttribute("pageTitle", "SQL Injection UNION-Based");
        model.addAttribute("attackType", "Injection UNION");
        model.addAttribute("description", "Testa UNION SELECT per estrarre dati da altre tabelle");
        return "union-injection";
    }

    /**
     * Elabora Injection UNION - Vulnerabile
     */
    @PostMapping("/union-injection/vulnerable")
    @ResponseBody
    public AttackResult unionInjectionVulnerable(@RequestParam String searchName) {
        try {
            long startTime = System.currentTimeMillis();
            String result = userService.searchUserByName(searchName);
            long duration = System.currentTimeMillis() - startTime;
            
            boolean attack = searchName.contains("UNION");

            boolean isVulnerable = attack && result != null;
            
            String message;
            if (isVulnerable && result != null) {
                if (result.toLowerCase().contains("sqlite")) {
                    message = "🚨 VULNERABILE! Versione database esposta: " + result;
                } else {
                    message = "🚨 VULNERABILE! Dati carta di credito esposti: " + result;
                }
            } else {
                message = "✅ Risultato ricerca normale";
            }
            
            return new AttackResult(
                isVulnerable,
                message,
                "SELECT name FROM users WHERE name LIKE '%" + searchName + "%'",
                duration,
                isVulnerable ? "CRITICAL" : "SAFE",
                result
            );
        } catch (Exception e) {
            return new AttackResult(false, "❌ Errore: " + e.getMessage(), "", 0, "ERROR");
        }
    }

    /**
     * Pagina di Test Injection Time-Based Blind
     */
    @GetMapping("/time-based-blind")
    public String timeBasedBlind(Model model) {
        model.addAttribute("pageTitle", "SQL Injection Time-Based Blind");
        model.addAttribute("attackType", "Time-Based Blind");
        model.addAttribute("description", "Testa la funzione SLEEP() per rilevare injection tramite tempo di risposta");
        return "time-based-blind";
    }

    /**
     * Elabora Time-Based Blind - Vulnerabile
     */
    @PostMapping("/time-based-blind/vulnerable")
    @ResponseBody
    public AttackResult timeBasedBlindVulnerable(@RequestParam String userId) {
        try {
            long startTime = System.currentTimeMillis();
            String result = userService.getUserEmail(userId);
            long duration = System.currentTimeMillis() - startTime;
            
            boolean attack = userId.contains("SLEEP");
            boolean isVulnerable = attack && result != null;
            
            return new AttackResult(
                isVulnerable,
                isVulnerable ? "🚨 VULNERABILE! SLEEP() eseguito - Durata: " + duration + "ms" : "✅ Query eseguita normalmente",
                "SELECT email FROM users WHERE id='" + userId + "'",
                duration,
                isVulnerable ? "CRITICAL" : "SAFE",
                result
            );
        } catch (Exception e) {
            return new AttackResult(false, "❌ Errore: " + e.getMessage(), "", 0, "ERROR");
        }
    }

    /**
     * Pagina di Test Injection Boolean-Based Blind
     */
    @GetMapping("/boolean-blind")
    public String booleanBlind(Model model) {
        model.addAttribute("pageTitle", "SQL Injection Boolean-Based Blind");
        model.addAttribute("attackType", "Boolean-Based Blind");
        model.addAttribute("description", "Testa SUBSTRING() per estrarre la password carattere per carattere");
        return "boolean-blind";
    }

    /**
     * Elabora Boolean Blind - Vulnerabile
     */
    @PostMapping("/boolean-blind/vulnerable")
    @ResponseBody
    public AttackResult booleanBlindVulnerable(@RequestParam String username) {
        try {
            long startTime = System.currentTimeMillis();
            boolean result = userService.checkUserExists(username);
            long duration = System.currentTimeMillis() - startTime;
            
            boolean isVulnerable = username.contains("SUBSTRING") && result;
            
            return new AttackResult(
                isVulnerable,
                isVulnerable ? "🚨 VULNERABILE! Injection boolean blind riuscita - Estrazione password possibile" : (result ? "✅ Utente esiste" : "✅ Utente non trovato"),
                "SELECT COUNT(*) FROM users WHERE username='" + username + "'",
                duration,
                isVulnerable ? "CRITICAL" : "SAFE",
                result ? "true" : "false"
            );
        } catch (Exception e) {
            return new AttackResult(false, "❌ Errore: " + e.getMessage(), "", 0, "ERROR");
        }
    }

    /**
     * Pagina di Test Injection Error-Based
     */
    @GetMapping("/error-based")
    public String errorBased(Model model) {
        model.addAttribute("pageTitle", "SQL Injection Error-Based");
        model.addAttribute("attackType", "Error-Based");
        model.addAttribute("description", "Testa errori di sintassi SQL per estrarre informazioni del database");
        return "error-based";
    }

    /**
     * Elabora Error-Based - Vulnerabile
     */
    @PostMapping("/error-based/vulnerable")
    @ResponseBody
    public AttackResult errorBasedVulnerable(@RequestParam String userId) {
        try {
            long startTime = System.currentTimeMillis();
            String result = userService.getUserPassword(userId);
            long duration = System.currentTimeMillis() - startTime;
            
            boolean isVulnerable = result != null && (result.contains("SQL ERROR") || result.contains("error") || result.contains("ERROR"));
            
            return new AttackResult(
                isVulnerable,
                isVulnerable ? "🚨 VULNERABILE! Messaggio errore SQL esposto: " + result : "✅ Query eseguita",
                "SELECT password FROM users WHERE id='" + userId + "'",
                duration,
                isVulnerable ? "CRITICAL" : "SAFE",
                result
            );
        } catch (Exception e) {
            return new AttackResult(false, "❌ Errore: " + e.getMessage(), "", 0, "ERROR");
        }
    }

    /**
     * Pagina di Test Injection Second Order
     */
    @GetMapping("/second-order")
    public String secondOrder(Model model) {
        model.addAttribute("pageTitle", "SQL Injection Second Order");
        model.addAttribute("attackType", "Second Order");
        model.addAttribute("description", "Memorizza payload malevolo nel database, poi eseguilo al recupero");
        return "second-order";
    }

    /**
     * Elabora Second Order - Vulnerabile (Crea Utente)
     */
    @PostMapping("/second-order/vulnerable/create")
    @ResponseBody
    public AttackResult secondOrderVulnerableCreate(@RequestParam String username, 
                                                     @RequestParam String password, 
                                                     @RequestParam String email) {
        try {
            long startTime = System.currentTimeMillis();
            int userId = userService.createUser(username, password, email);
            long duration = System.currentTimeMillis() - startTime;
            
            return new AttackResult(
                true,
                "✅ Utente creato con ID: " + userId + " (username malevolo memorizzato)",
                "INSERT INTO users (username, password, email) VALUES ('" + username + "', '" + password + "', '" + email + "')",
                duration,
                "INFO",
                "ID Utente: " + userId
            );
        } catch (Exception e) {
            return new AttackResult(false, "❌ Errore: " + e.getMessage(), "", 0, "ERROR");
        }
    }

    /**
     * Elabora Second Order - Vulnerabile (Ottieni Profilo)
     */
    @PostMapping("/second-order/vulnerable/profile")
    @ResponseBody
    public AttackResult secondOrderVulnerableProfile(@RequestParam String userId) {
        try {
            long startTime = System.currentTimeMillis();
            String result = userService.getUserProfile(userId);
            long duration = System.currentTimeMillis() - startTime;
            
            boolean isVulnerable = result != null && result.contains(",");
            
            return new AttackResult(
                isVulnerable,
                isVulnerable ? "🚨 VULNERABILE! Injection second order eseguita - Email multiple esposte: " + result : "✅ Singolo profilo restituito",
                "SELECT email FROM users WHERE id='" + userId + "'",
                duration,
                isVulnerable ? "CRITICAL" : "SAFE",
                result
            );
        } catch (Exception e) {
            return new AttackResult(false, "❌ Errore: " + e.getMessage(), "", 0, "ERROR");
        }
    }

    /**
     * Reset Database - Elimina e ricrea tutte le tabelle
     */
    @PostMapping("/reset-db")
    @ResponseBody
    public ResetResult resetDatabase() {
        try {
            // Legge ed esegue schema.sql
            java.io.InputStream is = getClass().getClassLoader().getResourceAsStream("schema.sql");
            if (is == null) {
                return new ResetResult(false, "File schema non trovato");
            }
            
            String schema = new String(is.readAllBytes());
            is.close();
            
            // Divide per punto e virgola ed esegue ogni statement
            java.sql.Connection conn = com.sqllib.utils.DatabaseConnection.getConnection();
            java.sql.Statement stmt = conn.createStatement();
            
            for (String sql : schema.split(";")) {
                sql = sql.trim();
                if (!sql.isEmpty()) {
                    stmt.execute(sql);
                }
            }
            
            stmt.close();
            conn.close();
            
            return new ResetResult(true, "Database ripristinato con successo! Tutte le tabelle ricreate con dati predefiniti.");
        } catch (Exception e) {
            return new ResetResult(false, "Ripristino database fallito: " + e.getMessage());
        }
    }

    /**
     * DTO Risultato Reset
     */
    public static class ResetResult {
        private boolean success;
        private String message;

        public ResetResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
    }

    /**
     * DTO Risultato Attacco
     */
    public static class AttackResult {
        private boolean vulnerable;
        private String message;
        private String query;
        private long duration;
        private String severity;
        private String data;

        public AttackResult(boolean vulnerable, String message, String query, long duration, String severity) {
            this(vulnerable, message, query, duration, severity, null);
        }

        public AttackResult(boolean vulnerable, String message, String query, long duration, String severity, String data) {
            this.vulnerable = vulnerable;
            this.message = message;
            this.query = query;
            this.duration = duration;
            this.severity = severity;
            this.data = data;
        }

        // Getters
        public boolean isVulnerable() { return vulnerable; }
        public String getMessage() { return message; }
        public String getQuery() { return query; }
        public long getDuration() { return duration; }
        public String getSeverity() { return severity; }
        public String getData() { return data; }
    }
}
