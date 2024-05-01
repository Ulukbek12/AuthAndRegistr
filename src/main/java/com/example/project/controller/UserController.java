package com.example.project.controller;


import com.example.project.dto.LoginDto;
import com.example.project.dto.RegisterDto;
import com.example.project.services.UserService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@FieldDefaults(makeFinal = true,level = AccessLevel.PRIVATE)
public class UserController {

    UserService userService;

    @PostMapping("/auth")
    public ResponseEntity<String> authenticate(@RequestBody LoginDto loginDto){
        return userService.authenticate(loginDto);
    }
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterDto registerDto){
        return userService.register(registerDto);
    }
    @GetMapping("/home")
    ResponseEntity<String> home(){
        return userService.home();
    }

}
