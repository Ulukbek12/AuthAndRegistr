package com.example.project.repository;

import com.example.project.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

public interface UserRepository extends JpaRepository<User,Long> {
    UserDetails findByUsername(String username);
    UserDetails findByEmail(String email);
}
