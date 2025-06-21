package com.example.stage3.controller;

import com.example.stage3.dto.AuthenticationRequest;
import com.example.stage3.dto.AuthenticationResponse;
import com.example.stage3.dto.RefreshTokenRequest;
import com.example.stage3.service.AuthenticationService;
import com.example.stage3.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequiredArgsConstructor
@RequestMapping("/api")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;

    // The authenticateUser() method takes in an AuthenticationRequest object, which contains the username and password.
    // The method returns an AuthenticationResponse object, which contains the JWT and refresh token, and the user's roles.
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody AuthenticationRequest authenticationRequest) {
        try {
            AuthenticationResponse authResponse = authenticationService.authenticate(authenticationRequest);
            System.out.println("logging in: ");
            System.out.println("username: " + authenticationRequest.getUsername());
            System.out.println("jwt token: " + authResponse.getAccessToken());
            System.out.println("refresh token: " + authResponse.getRefreshToken());
            return ResponseEntity.ok(authResponse);
        } catch (AuthenticationServiceException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    // The refreshToken() method takes in a RefreshTokenRequest object, which contains the refresh token.
    // The method returns an AuthenticationResponse object, which contains the JWT and refresh token,
    // and the user's roles.
    @PostMapping("/refresh_token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        try {
            AuthenticationResponse authResponse = refreshTokenService.refreshTokens(refreshTokenRequest.getRefreshToken());
            if (authResponse == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh Token error. Please login again");
            }
            System.out.println("refreshing the token: ");
            System.out.println("jwt token: " + authResponse.getAccessToken());
            System.out.println("refresh token: " + authResponse.getRefreshToken());
            return ResponseEntity.ok(authResponse);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
}