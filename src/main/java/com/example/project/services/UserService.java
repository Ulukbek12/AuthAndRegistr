package com.example.project.services;

import com.example.project.config.JwtUtils;
import com.example.project.dto.LoginDto;
import com.example.project.dto.RegisterDto;
import com.example.project.entities.User;
import com.example.project.repository.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class UserService {

    UserRepository userRepository;

    PasswordEncoder passwordEncoder;

    AuthenticationManager authenticationManager;

    JwtUtils jwtUtils;
    static Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z]+@[A-Za-z]+\\.[A-Za-z]+$");

    static Pattern VALID_CHARACTERS_PATTERN = Pattern.compile("^[a-zA-Z]+$");

    public ResponseEntity<String> authenticate(LoginDto loginDto) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword())
            );
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("No such a user");
        }

        final UserDetails userDetails = userRepository.findByUsername(loginDto.getUsername());
        if (userDetails != null) {
            String token = jwtUtils.generateToken(userDetails);
            return ResponseEntity.ok().body("You have successfully logged in");
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("..");
        }
    }

    public ResponseEntity<String> register(RegisterDto registerDto) {
        if (userRepository.findByUsername(registerDto.getUsername()) != null ||
                userRepository.findByEmail(registerDto.getEmail()) != null) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User with this username or email already exists");
        }
        User user = new User();

        String email = registerDto.getEmail();
        if(!EMAIL_PATTERN.matcher(email).matches()){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email does not match to requirements");
        }

        String username = registerDto.getUsername();
        if(!VALID_CHARACTERS_PATTERN.matcher(username).matches()){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username does not match to requirements");
        }

        String password = registerDto.getPassword();
        String repeatedPassword = registerDto.getRepeatedPassword();
        if(!isValidPassword(password)){
            return  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Password does not match to requirements");
        }
        if (!isValidPassword(repeatedPassword)) {
            return  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Repeated password does not match to requirements");
        }
        if(!password.equals(repeatedPassword)){
            return  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Passwords do not match to each other");
        }
        //если все валидации пройдены
        user.setEmail(email);
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));

        userRepository.save(user);
        return ResponseEntity.ok().body("User registered successfully");
    }
    public ResponseEntity<String> home(){
        return ResponseEntity.ok().body("Home....");
    }
    public boolean isValidPassword(String password){
        if (password == null) {
            return false;
        }
        if(password.length() < 8 || password.length() > 15){
            return false;
        }
        if(!password.matches(".*[a-z].*") || !password.matches(".*[A-Z].*")){
            return false;
        }
        if(!password.matches(".*\\d.*")){
            return false;
        }
        if(!password.matches(".*[!@#%^&*].*")){
            return false;
        }
        return true;
    }
}

