package com.example.stage1.controller;

import com.example.stage1.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import com.example.stage1.dto.AuthenticationRequest;
import com.example.stage1.dto.AuthenticationResponse;

@Controller
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    // The authenticateUser() method takes in an AuthenticationRequest object, which contains the username and password.
    // The method returns an AuthenticationResponse object, which contains the JWT and refresh token, and the user's roles.
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody AuthenticationRequest authenticationRequest) {
        try {
            AuthenticationResponse authResponse = authenticationService.authenticate(authenticationRequest);
            System.out.println("username: " + authenticationRequest.getUsername());
            System.out.println("jwt token: " + authResponse.getAccessToken());
            return ResponseEntity.ok(authResponse);
        } catch (AuthenticationServiceException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    @GetMapping("/welcome")
    public ResponseEntity<String> welcome() {
        return ResponseEntity.ok("Welcome to the Stage 1 application!");
    }
}