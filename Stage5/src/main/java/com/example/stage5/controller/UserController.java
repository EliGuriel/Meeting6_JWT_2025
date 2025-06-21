package com.example.stage5.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
        return "welcome to the home page";
    }

}
