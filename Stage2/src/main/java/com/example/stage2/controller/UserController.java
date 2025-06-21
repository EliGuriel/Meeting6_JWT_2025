package com.example.stage2.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

/*
    +------------------------------------------------+
    TODO : Stage 2 added this controller, user controller
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {

    @GetMapping("/protected-message")
    public String home() {
        return "Welcome to the Backend Server home page";
    }

    @GetMapping("/protected-message-admin")
    public String adminHome() {
        return "Welcome to the Backend Server ADMIN home page";
    }

}
