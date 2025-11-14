package com.sqllib.controllers;

import java.sql.SQLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.sqllib.services.UserService;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/{id}")
    public String getUserById(@PathVariable String id) throws SQLException {
        // VULNERABILE a SQL Injection
        return userService.getUserById(id);
    }

    @PostMapping("/")
    public String createUser(@RequestParam String username, @RequestParam String password, @RequestParam String email) throws SQLException {
        // VULNERABILE a SQL Injection
        int userId = userService.createUser(username, password, email);
        return "User created with ID: " + userId;
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) throws SQLException {
        // VULNERABILE a SQL Injection
        boolean authenticated = userService.authenticate(username, password);
        return authenticated ? "Login successful" : "Login failed";
    }

    @GetMapping("/profile/{userId}")
    public String getUserProfile(@PathVariable String userId) throws SQLException {
        // VULNERABILE a SQL Injection Second Order
        return userService.getUserProfile(userId);
    }

    @GetMapping("/exists/{username}")
    public String checkUserExists(@PathVariable String username) throws SQLException {
        // VULNERABILE a SQL Injection Boolean-based Blind
        boolean exists = userService.checkUserExists(username);
        return exists ? "User exists" : "User not found";
    }

    @GetMapping("/email/{userId}")
    public String getUserEmail(@PathVariable String userId) throws SQLException {
        // VULNERABILE a SQL Injection Time-based Blind
        return userService.getUserEmail(userId);
    }

    @GetMapping("/search")
    public String searchUserByName(@RequestParam String username) throws SQLException {
        // VULNERABILE a SQL Injection UNION-based
        return userService.searchUserByName(username);
    }
    
    @GetMapping("/password/{userId}")
    public String getUserPassword(@PathVariable String userId) throws SQLException {
        // VULNERABILE a SQL Injection Error-Based
        return userService.getUserPassword(userId);
    }
}