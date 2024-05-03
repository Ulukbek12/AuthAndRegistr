package com.example.project.interfaces;

import com.example.project.dto.LoginDto;
import com.example.project.dto.RegisterDto;
import org.springframework.http.ResponseEntity;

public interface UserInterface {
     ResponseEntity<String> register(RegisterDto registerDto);
     ResponseEntity<String> authenticate(LoginDto loginDto);
     boolean isValidEmail(String email);
     boolean isValidLogin(String login);
     boolean isValidPassword(String password);
}
