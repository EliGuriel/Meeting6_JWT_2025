package com.example.stage1.repository;

import com.example.stage1.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findUserByUsername(String username);
    User findByUsername(String username);
}
