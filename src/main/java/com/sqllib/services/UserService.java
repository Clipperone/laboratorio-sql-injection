package com.sqllib.services;

import java.sql.SQLException;

import org.springframework.stereotype.Service;

import com.sqllib.repositories.UserRepository;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService() {
        this.userRepository = new UserRepository();
    }

    // VULNERABLE methods using string concatenation
    
    public String getUserById(String id) throws SQLException {
        return userRepository.getUserById(id);
    }

    public int createUser(String username, String password, String email) throws SQLException {
        return userRepository.createUser(username, password, email);
    }

    public boolean authenticate(String username, String password) throws SQLException {
        return userRepository.authenticate(username, password);
    }

    public String getUserProfile(String userId) throws SQLException {
        return userRepository.getUserProfile(Integer.parseInt(userId));
    }

    public boolean checkUserExists(String username) throws SQLException {
        return userRepository.checkUserExists(username);
    }

    public String getUserEmail(String userId) throws SQLException {
        return userRepository.getUserEmail(userId);
    }

    public String searchUserByName(String username) throws SQLException {
        return userRepository.searchUserByName(username);
    }
    
    public String getUserPassword(String userId) throws SQLException {
        return userRepository.getUserPassword(userId);
    }
}