# SQL Injection Lab 🔒

Un laboratorio completo per testare e comprendere le **vulnerabilità SQL Injection** nelle applicazioni Java. Questo progetto dimostra approcci vulnerabili alle interazioni con il database utilizzando Spring Boot e JDBC **esclusivamente per scopi educativi**.

## 🎯 Scopo del Progetto

Questo progetto è stato progettato per gli sviluppatori per:
- Comprendere i vettori di attacco SQL Injection
- Imparare a identificare pattern di codice vulnerabili
- Analizzare le tecniche di attacco SQL Injection
- Studiare le vulnerabilità di sicurezza nelle applicazioni web

## 📋 Prerequisiti

- **Java 21** o superiore
- **Maven 3.8.9** o superiore
- **Spring Boot 3.5.7** (con Spring Web MVC e Thymeleaf)
- **Database SQLite** (embedded, in-memory con funzione SLEEP() personalizzata per test basati sul tempo)
- **Browser Web Moderno** (Chrome, Firefox, Edge, Safari) per accedere all'interfaccia web interattiva

## 🔍 Riepilogo Attacchi SQL Injection

Questo progetto implementa **7 tipi** di attacchi SQL Injection con implementazioni vulnerabili:

| Tipo di Attacco | Implementato | Esempio | Impatto |
|----------------|--------------|---------|---------|
| First Order | ✅ Sì | `1' OR '1'='1` | Estrazione diretta dei dati |
| Authentication Bypass | ✅ Sì | `admin'--` o `' OR '1'='1` | Bypassa il login |
| Second Order | ✅ Sì | Memorizza `malicious' OR '1'='1` poi esegue | Exploit ritardato |
| Boolean-based Blind | ✅ Sì | `admin' AND SUBSTRING(password,1,1)='s` | Estrazione carattere per carattere |
| Time-based Blind | ✅ Sì | `1' AND SLEEP(5)--` | Estrazione basata sui tempi con funzione SLEEP() personalizzata |
| UNION-based | ✅ Sì | `' UNION SELECT credit_card FROM sensitive_data--` | Estrazione dati da più tabelle |
| Error-Based | ✅ Sì | `1'` o `1 AND invalid_column=1` | Estrazione dati tramite messaggi di errore |

## 🏗️ Struttura del Progetto

```
sql-injection-lab/
├── src/
│   ├── main/
│   │   ├── java/com/sqllib/
│   │   │   ├── App.java                              # Punto di ingresso dell'applicazione Spring Boot
│   │   │   ├── controllers/
│   │   │   │   ├── UserController.java               # Endpoint REST API (VULNERABILI - 10 endpoint)
│   │   │   │   └── WebViewController.java            # Controller Web UI (7 pagine di attacco + dashboard)
│   │   │   ├── services/
│   │   │   │   └── UserService.java                  # Logica Business (VULNERABILE)
│   │   │   ├── repositories/
│   │   │   │   └── UserRepository.java               # Accesso ai Dati (VULNERABILE)
│   │   │   ├── config/
│   │   │   │   └── DataSourceDirectoryInitializer.java  # Inizializzatore directory database
│   │   │   └── utils/
│   │   │       └── DatabaseConnection.java           # Utility Connessione Database
│   │   └── resources/
│   │       ├── application.properties                # Configurazione Applicazione
│   │       ├── schema.sql                            # Schema Database
│   │       ├── static/                               # Risorse statiche (CSS, JS, immagini)
│   │       │   └── css/
│   │       │       ├── dashboard.css                 # Stili centralizzati per dashboard
│   │       │       └── attack-pages.css              # Stili centralizzati per pagine di attacco
│   │       └── templates/                            # Template HTML Thymeleaf
│   │           ├── dashboard.html                    # Pagina principale con 7 card di attacco
│   │           ├── auth-bypass.html                  # Pagina attacco Authentication Bypass
│   │           ├── user-retrieval.html               # Pagina attacco Data Retrieval
│   │           ├── union-injection.html              # Pagina attacco UNION-Based
│   │           ├── time-based-blind.html             # Pagina attacco Time-Based Blind
│   │           ├── boolean-blind.html                # Pagina attacco Boolean-Based Blind
│   │           ├── error-based.html                  # Pagina attacco Error-Based
│   │           └── second-order.html                 # Pagina attacco Second Order
│   │
│   └── test/
│       ├── java/com/sqllib/
│       │   └── UserServiceTests.java                 # Test Integrazione (Vulnerabili - 8 test FALLISCONO quando l'injection funziona)
│       └── resources/
│           ├── application.properties                # Configurazione Test
│           ├── schema.sql                            # Schema Database Test
│           └── init-test-db.sql                      # Inizializzazione Database Test
│
├── data/                                              # Directory database SQLite (creata automaticamente)
│   └── sqllib.db                                     # File database SQLite persistente
│
├── pom.xml                                            # Configurazione Maven
├── .gitignore                                         # Regole Git Ignore
├── SQL-Injection-Lab-Vulnerable.postman_collection.json  # Collezione Postman
└── README.md                                          # Documentazione progetto
```

## 🔄 Panoramica Architettura

Questo progetto utilizza un'**architettura a tre livelli** con **implementazioni vulnerabili** per scopi educativi, più un'**interfaccia web interattiva** per il testing:

### **🌐 INTERFACCIA WEB (Testing Interattivo)**
```
Browser → GET /auth-bypass
    ↓
WebViewController
    ↓
Template Thymeleaf (dashboard.html, auth-bypass.html, ecc.)
    ↓
L'utente clicca "Test Attacco" → POST /api/users?username=admin'--
    ↓
Flusso REST API (vedi sotto)
```

### **🔴 PERCORSO VULNERABILE (Scopi Educativi)**
```
GET /api/users/{id}
    ↓
UserController (Vulnerabile)
    ↓
UserService (Vulnerabile)
    ↓
UserRepository (Concatenazione Stringhe - VULNERABILE)
    ↓
Database (Rischio SQL Injection!)
```

## 🚀 Avvio Rapido

### 1. **Compilare il Progetto**

```bash
# Compilare senza eseguire i test
mvn clean package -DskipTests

# Compilare con i test
mvn clean package
```

### 2. **Eseguire l'Applicazione**

```bash
# Opzione 1: Usando Maven
mvn spring-boot:run -DskipTests

# Opzione 2: Eseguire il file JAR
java -jar target/sql-injection-lab-1.0.0.jar
```

L'applicazione si avvierà su **`http://localhost:8080`**

### 3. **Accedere all'Interfaccia Web** 🌐

L'applicazione include un'**interfaccia web interattiva** per testare gli attacchi SQL injection attraverso il browser:

**URL Dashboard**: `http://localhost:8080`

#### **Funzionalità**:
- 🎨 **UI Moderna con 7 Card di Attacco**: Ogni card rappresenta una diversa tecnica di SQL injection
- 🔴 **Sezione Vulnerabile**: Testa i payload e vedi come funziona la SQL injection in tempo reale
-  **Payload Click-to-use**: Esempi di attacco preconfigurati che popolano automaticamente i campi di input
- 🎯 **Effetti Hover**: Feedback visivo sugli elementi interattivi
- 🔄 **Pulsante Reset Database**: Ripristina il database allo stato iniziale con un click
- 📊 **Risultati in Tempo Reale**: Vedi l'esecuzione della query, il tempo di risposta e i risultati dell'attacco
- 🔍 **Syntax Highlighting**: Evidenziazione SQL con Prism.js per migliore leggibilità
- 🎓 **Focus Educativo**: Impara i vettori di attacco SQL Injection

#### **Pagine di Attacco Disponibili**:
1. **Authentication Bypass** - `/auth-bypass` - Bypassa il login usando commenti SQL e OR injection
2. **User Data Retrieval** - `/user-retrieval` - Estrae record multipli usando OR injection
3. **UNION-Based** - `/union-injection` - Estrae dati da altre tabelle usando UNION SELECT
4. **Time-Based Blind** - `/time-based-blind` - Rileva l'injection tramite ritardi nella risposta
5. **Boolean-Based Blind** - `/boolean-blind` - Estrae dati carattere per carattere
6. **Error-Based** - `/error-based` - Estrae informazioni tramite messaggi di errore SQL
7. **Second Order** - `/second-order` - Memorizza il payload, poi esegue al recupero

#### **Come Usare**:
1. Naviga su `http://localhost:8080`
2. Clicca su qualsiasi card di attacco per aprire la pagina di test
3. Clicca sui payload di esempio per popolare i campi di input
4. Invia per vedere l'attacco in azione
5. Usa il pulsante "Reset Database" per ripristinare lo stato iniziale

### 4. **Usare la Collezione Postman**

Importa la collezione Postman fornita per testare tutti gli endpoint vulnerabili con esempi di attacco preconfigurati:

1. Apri Postman
2. Clicca **Import** (in alto a sinistra)
3. Seleziona il file: `SQL-Injection-Lab-Vulnerable.postman_collection.json`
4. Assicurati che l'applicazione sia in esecuzione su `http://localhost:8080`
5. Sfoglia la collezione per testare ciascuno dei 7 tipi di SQL Injection

**Funzionalità della Collezione:**
- ✅ **18 richieste preconfigurate** con payload di attacco
- ✅ Organizzate per tipo di SQL Injection (7 categorie)
- ✅ Esempi sia legittimi che malevoli
- ✅ Descrizioni dettagliate per ogni attacco
- ✅ Pronta all'uso - basta importare e testare!

## 🔌 Endpoint API

### **🔴 Endpoint Vulnerabili** ⚠️ (Percorso: `/api/users`)

Questi endpoint dimostrano vulnerabilità SQL Injection usando concatenazione di stringhe:

**1. Ottieni Utente per ID (First Order SQL Injection)**
```bash
GET http://localhost:8080/api/users/{id}
```
Esempio attacco: `http://localhost:8080/api/users/1' OR '1'='1`
- **Risultato attacco**: Restituisce TUTTI gli utenti (admin, user, test) invece di uno solo

**2. Login (Authentication Bypass)**
```bash
POST http://localhost:8080/api/users/login
Content-Type: application/x-www-form-urlencoded

username=admin&password=secret123
```
Esempi di attacco:
```bash
# Bypass con Commento SQL
username=admin'--&password=anything

# Bypass con OR 1=1
username=hackerr'' or 1=1--&password=anything
```
- **Risultato attacco**: Login senza password valida

**3. Second Order SQL Injection - Step 1: Memorizza Username Malevolo**
```bash
POST http://localhost:8080/api/users/
Content-Type: application/x-www-form-urlencoded

username=hackerr'' or 1=1--&password=password123&email=hacker@example.com
```
- Memorizza il payload SQL malevolo nel **campo username**
- **Risposta**: `User created with ID: 4` (copia questo ID per lo Step 2!)

**4. Second Order SQL Injection - Step 2: Esegui Injection Memorizzata**
```bash
GET http://localhost:8080/api/users/profile/4
```
- **Risultato attacco**: Restituisce TUTTE le email degli utenti invece di una sola

**5. Verifica Esistenza Utente (Boolean-based Blind SQL Injection)**
```bash
GET http://localhost:8080/api/users/exists/{username}
```
Esempi di attacco:
```bash
# Estrai 1° carattere della password
http://localhost:8080/api/users/exists/admin' AND SUBSTR(password,1,1)='s

# Estrai 2° carattere della password
http://localhost:8080/api/users/exists/admin' AND SUBSTR(password,2,1)='e
```
- **Risultato attacco**: Restituisce true/false per rivelare i caratteri della password

**6. Ottieni Email Utente (Time-based Blind SQL Injection)**
```bash
GET http://localhost:8080/api/users/email/{userId}
```
Esempio attacco:
```bash
# Attacco basato sul tempo con funzione SLEEP() personalizzata
http://localhost:8080/api/users/email/1' AND SLEEP(5)--
```
- **Risultato attacco**: La risposta impiega ~5 secondi se l'injection ha successo

**7. Cerca Utenti per Nome (UNION-based SQL Injection)**
```bash
GET http://localhost:8080/api/users/search?username={username}
```
Esempi di attacco:
```bash
# Estrai carte di credito dalla tabella sensitive_data
http://localhost:8080/api/users/search?username=' UNION SELECT credit_card FROM sensitive_data--

# Estrai numeri SSN
http://localhost:8080/api/users/search?username=' UNION SELECT ssn FROM sensitive_data--
```
- **Risultato attacco**: Restituisce dati sensibili invece degli username

**8. Ottieni Password Utente (Error-Based SQL Injection)**
```bash
GET http://localhost:8080/api/users/password/{userId}
```
Esempio attacco:
```bash
# Sintassi SQL non valida - espone messaggio di errore del database
http://localhost:8080/api/users/password/1'
```
- **Risultato attacco**: Messaggi di errore espongono struttura query e informazioni database

---

## � Esempi di Attacchi

### **Implementazione Vulnerabile (UserRepository)**
```java
// ❌ VULNERABILE - Concatenazione stringhe
public String getUserById(String id) throws SQLException {
    String query = "SELECT username FROM users WHERE id = '" + id + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    // Attacco: id = "1' OR '1'='1" → Restituisce sempre risultati!
}
```



## 🧪 Esecuzione Test

### Esegui Tutti i Test
```bash
mvn test
```

### Esegui Classe di Test Specifica
```bash
# Test Integrazione (Layer Service)
mvn test -Dtest=UserServiceTests                # Test implementazione vulnerabile (8 test)
```

### Esegui Metodo di Test Specifico
```bash
# Esempio: Esegui solo test UNION-based injection
mvn test "-Dtest=UserServiceTests#testUNIONBasedInjection"

# Esempio: Esegui solo test authentication bypass
mvn test "-Dtest=UserServiceTests#testAuthenticationBypassVulnerable"
```

### Salta i Test Durante la Compilazione
```bash
mvn clean package -DskipTests
```

### Filosofia dei Test

**Test Vulnerabili (UserServiceTests)**:
- 💥 I test **FALLISCONO** quando la SQL injection ha successo
- Test fallito = vulnerabilità rilevata nel codice
- Ogni fallimento include payload e dati esposti
- Uso in CI/CD: test vulnerabili falliti indicano problemi di sicurezza

### Riepilogo Copertura Test
```
❌ UserServiceTests (8 test) - Test FALLISCONO quando SQL injection ha successo

Totale: 8 test di integrazione usando @SpringBootTest con database SQLite in-memory
```

## 📊 Stack Tecnologico

| Componente | Versione | Scopo |
|-----------|---------|-------|
| Spring Boot | 3.5.7 | Framework Web |
| Java | 21 | Ambiente Runtime |
| SQLite | 3.49.1.0 | Database embedded in-memory con funzione SLEEP() personalizzata |
| JUnit 5 | Latest | Testing Integrazione |
| Maven | 3.8.9+ | Strumento Build |
| Thymeleaf | Latest | Template Engine |
| Bootstrap | 5.3.2 | Framework CSS |
| Font Awesome | 6.4.2 | Libreria Icone |
| Prism.js | 1.29.0 | Evidenziazione Sintassi SQL |

## 📝 Configurazione Applicazione

**`application.properties`**
```properties
spring.application.name=sql-injection-lab
server.port=8080

# Configurazione Database SQLite con funzione SLEEP() personalizzata
spring.datasource.url=jdbc:sqlite:data/sqllib.db
spring.datasource.driverClassName=org.sqlite.JDBC
spring.datasource.username=
spring.datasource.password=

# Inizializza schema database all'avvio
spring.sql.init.mode=always
```

## 🗄️ Schema Database

**Tabella Users**
```sql
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL
);
```

**Tabella Sensitive Data**
```sql
CREATE TABLE sensitive_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
    secret_key VARCHAR(255),
    credit_card VARCHAR(16),
    ssn VARCHAR(11)
);
```

## 🎯 Tipi di SQL Injection Dimostrati

### 1. **First Order SQL Injection**
Injection diretta dove l'input malevolo viene immediatamente usato in una query SQL.

**Esempio Attacco:**
```bash
GET /api/users/1' OR '1'='1
# Restituisce: "admin, user, test" - TUTTI gli utenti invece di uno solo!
```

### 2. **Authentication Bypass**
Caso speciale di First Order injection che prende di mira i meccanismi di login.

**Esempi Attacco:**
```bash
# Bypass basato su commenti
username: admin'--
password: anything

# Bypass basato su OR
username: hackerr'' or 1=1--
password: anything
```

### 3. **Second Order SQL Injection**
Dati malevoli vengono prima memorizzati nel database, poi eseguiti in una query successiva quando recuperati.

**Flusso:**
1. **Fase Memorizzazione:** L'utente crea un account con username malevolo: `hackerr'' or 1=1--`
2. **Fase Recupero:** Il sistema recupera lo username per ID dal database
3. **Fase Esecuzione:** Il sistema usa lo username recuperato in un'altra query senza sanitizzazione (VULNERABILE!)

### 4. **Boolean-based Blind SQL Injection**
Estrae dati carattere per carattere osservando risposte vero/falso.

**Esempio Attacco:**
```bash
# Estrai primo carattere della password admin
GET /api/users/exists/admin' AND SUBSTRING(password,1,1)='s
# Se restituisce true, il primo carattere è 's'
```

### 5. **Time-based Blind SQL Injection**
Estrae dati causando ritardi deliberati e misurando i tempi di risposta.

**Esempio Attacco:**
```bash
# Attacco time-based con funzione SLEEP() personalizzata
GET /api/users/email/1' AND SLEEP(5)--
# La risposta impiega ~5 secondi se l'injection ha successo
```

### 6. **UNION-based SQL Injection**
Combina risultati da query SELECT multiple per estrarre dati da altre tabelle.

**Esempio Attacco:**
```bash
# Attacco UNION estrae numeri carte di credito dalla tabella sensitive_data
GET /api/users/search?username=' UNION SELECT credit_card FROM sensitive_data--
# Restituisce: 4532111122223333, 5555666677778888
# CRITICO: Espone dati finanziari da tabella diversa!
```

### 7. **Error-Based SQL Injection**
Estrae dati sensibili forzando il database a generare messaggi di errore che rivelano informazioni.

**Esempio Attacco:**
```bash
# Sintassi SQL non valida scatena errore
GET /api/users/password/1'

# Risposta: "SQL ERROR: [SQLITE_ERROR] SQL error or missing database (unrecognized token: "'")"
```

**Informazioni Esposte:**
- Struttura query e sintassi
- Tipo di database (SQLite, MySQL, ecc.)
- Esistenza tabelle e colonne
- Dettagli errore che aiutano a creare ulteriori attacchi

## 📚 Obiettivi di Apprendimento

Dopo aver lavorato con questo progetto, dovresti comprendere:

1. ✅ **Fondamenti SQL Injection** - Cos'è la SQL Injection e come funziona
2. ✅ **Vettori di Attacco** - 7 diversi tipi di attacchi SQL Injection
3. ✅ **Pattern Codice Vulnerabile** - Concatenazione stringhe e perché è pericolosa
4. ✅ **Architettura a Livelli** - Come separare le responsabilità attraverso tre tier
5. ✅ **Testing Integrazione** - Scrivere test che usano database reali per dimostrare vulnerabilità
6. ✅ **Attacchi Second Order** - Comprendere vulnerabilità ad esecuzione ritardata
7. ✅ **Tecniche Blind Injection** - Estrazione dati senza output diretto della query
8. ✅ **Attacchi UNION-based** - Estrarre dati da più tabelle simultaneamente
9. ✅ **Attacchi Error-Based** - Sfruttare messaggi di errore per estrarre dati sensibili

## ⚠️ Note Importanti sulla Sicurezza

**⚠️ AVVERTIMENTO:** Questo progetto contiene codice intenzionalmente vulnerabile a scopi educativi. **NON usare questo codice in produzione!**

### Strategia Organizzazione File

Il progetto mantiene **due implementazioni parallele**:

- **Percorso Vulnerabile** (`UserRepository`, `UserService`, `UserController`)
  - Scopo: Dimostrare vulnerabilità SQL Injection
  - Usato in testing e insegnamento
  - Contiene falle di sicurezza intenzionali

### Best Practices per Produzione:
1. **Usa sempre query parametrizzate** o framework ORM (Hibernate, JPA)
2. **Valida e sanitizza** tutti gli input utente
3. **Usa il principio del minimo privilegio** per gli account database
4. **Implementa autenticazione e autorizzazione appropriate**
5. **Usa Web Application Firewalls (WAF)** per protezione aggiuntiva
6. **Mantieni aggiornate le dipendenze** per evitare vulnerabilità note
7. **Esegui audit di sicurezza regolari** e penetration testing

## 🔧 Funzionalità Aggiuntive

### **Creazione Automatica Directory Database**
L'applicazione crea automaticamente la cartella `data/` se non esiste:
- ✅ `DataSourceDirectoryInitializer` - Crea la directory prima dell'inizializzazione Spring Boot
- ✅ `DatabaseConnection.ensureDataDirectoryExists()` - Crea la directory per connessioni JDBC dirette
- ✅ Nessuna configurazione manuale richiesta

### **Funzione SLEEP() Personalizzata**
Implementazione personalizzata della funzione SLEEP() per SQLite:
```java
// Registrata in DatabaseConnection.registerSleepFunction()
// Permette attacchi time-based blind come MySQL
SELECT * FROM users WHERE id=1 AND SLEEP(5)
```

## 📚 Risorse Aggiuntive

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Top 10](https://owasp.org/Top10/)
- [Spring Security Documentation](https://spring.io/projects/spring-security)
- [Java JDBC Best Practices](https://docs.oracle.com/javase/tutorial/jdbc/)

## 🤝 Contribuire

I contributi sono benvenuti! Sentiti libero di:
- Segnalare problemi o vulnerabilità
- Suggerire miglioramenti
- Aggiungere più casi di test
- Migliorare la documentazione

## 📄 Licenza

Questo progetto è fornito così com'è a scopi educativi.

## 👨‍💻 Autore

Creato come laboratorio educativo per il testing e l'apprendimento delle vulnerabilità SQL Injection.

---

**Ultimo Aggiornamento:** 12 Novembre 2025  
**Versione Spring Boot:** 3.5.7  
**Versione Java:** 21  
**Suite Test:** 8 test di integrazione - dimostrano come le SQL injection sfruttano codice vulnerabile  
**Tipi SQL Injection:** 7 tipi implementati  
**Endpoint API:** 8 endpoint vulnerabili per scopi educativi  
**Interfaccia Web:** 7 pagine di attacco + dashboard interattiva  
**Funzionalità Personalizzate:** Funzione SLEEP() per testing SQL injection time-based
