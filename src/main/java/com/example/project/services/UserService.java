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

@Service
@RequiredArgsConstructor
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class UserService {

    UserRepository userRepository;

    PasswordEncoder passwordEncoder;

    AuthenticationManager authenticationManager;

    JwtUtils jwtUtils;

    public ResponseEntity<String> register(RegisterDto registerDto) {
        if (userRepository.findByUsername(registerDto.getUsername()) != null ||
                userRepository.findByEmail(registerDto.getEmail()) != null) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User with this username or email already exists");
        }
        User user = new User();

        String email = registerDto.getEmail();
        if(!isValidEmail(email)){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email does not match to requirements");
        }

        String username = registerDto.getUsername();
        if(!isValidLogin(username)){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username does not match to requirements");
        }

        String password = registerDto.getPassword();
        String repeatedPassword = registerDto.getRepeatedPassword();
        if(!isValidPassword(password)){
            return  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Password does not match to requirements");
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

    public ResponseEntity<String> home(){
        return ResponseEntity.ok().body("Home....");
    }
    public boolean isValidEmail(String email) {
        // Проверяем, что строка не пуста и содержит символ '@'
        if (email == null || !email.contains("@")) {
            System.out.println("Поле почты является пустым или не содержит @");
            return false;
        }

        // Разделяем строку по символу '@' на две части
        String[] parts = email.split("@");
        if (parts.length != 2) {
            return false; // Если в адресе нет или более одного символа '@', он недопустим
        }

        // Проверяем, что обе части не пусты
        String username = parts[0];
        String domain = parts[1];
        if (username.isEmpty() || domain.isEmpty()) {
            System.out.println("Одна из частей или обе части являются пустыми");
            return false;
        }

        // Проверяем, что в домене есть хотя бы одна точка
        if (!domain.contains(".")) {
            System.out.println("Домен не содержит одну точку ");
            return false;
        }

        // Проверяем, что в имени пользователя и домене нет недопустимых символов
        if (!username.matches("[a-zA-Z0-9]+") || !domain.matches("[a-zA-Z0-9.]+")) {
            System.out.println("В имени пользователя или в домене есть недопустимые символы");
            return false;
        }
        return true;
    }


    public boolean isValidLogin(String login){
        // Проверяем, что login содержит только прописные и строчные английские буквы
        if (!login.matches("[a-zA-Z]+")) {
            System.out.println("Отсутствуют буквы английского алфавита верхнего или нижнего регистра");
            return false;
        }
        return true;
    }
    public boolean isValidPassword(String password){
        if (password == null) {
            System.out.println("Пароль равен null");
            return false;
        }
        if(password.length() < 8 || password.length() > 15){
            System.out.println("Длина пароля не в допустимом диапазоне");
            return false;
        }
        // Проверяем, что login содержит только прописные и строчные английские буквы
        if (!password.matches("[a-zA-Z]+")) {
            System.out.println("Отсутствуют английские буквы верхнего или нижнего регистра");
            return false;
        }
        if(!password.matches(".*\\d.*")){
            System.out.println("Отсутствуют цифры");
            return false;
        }
        if(!password.matches(".*[!@#%^&*].*")){
            System.out.println("Отсутствуют специальные символы");
            return false;
        }
        return true;
    }

}

