package com.example.stage4.controller;

import com.example.stage4.dto.AuthenticationRequest;
import com.example.stage4.dto.AuthenticationResponse;
import com.example.stage4.service.AuthenticationService;
import com.example.stage4.service.RefreshTokenService;
import com.example.stage4.dto.RefreshTokenRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * AuthenticationController - Updated for Stateless Architecture
 * 
 * This controller has been updated to support the new stateless approach
 * where IP addresses are embedded in JWT tokens as claims rather than
 * stored in the database.
 */
@Controller
@RequiredArgsConstructor
@RequestMapping("/api")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;

    /**
     * Authenticate user and generate JWT tokens with embedded IP address
     * 
     * @param authenticationRequest Contains username and password
     * @param request HTTP request to extract IP address
     * @return JWT access token and refresh token with IP claims
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody AuthenticationRequest authenticationRequest, 
                                              HttpServletRequest request) {
        try {
            // Extract IP address from request
            String ipAddress = request.getRemoteAddr();
            
            // Authenticate and generate tokens with IP embedded
            AuthenticationResponse authResponse = authenticationService.authenticate(authenticationRequest, ipAddress);
            
            System.out.println("Login successful for user: " + authenticationRequest.getUsername());
            System.out.println("IP address: " + ipAddress);
            System.out.println("Access token generated: " + authResponse.getAccessToken());
            System.out.println("Refresh token generated: " + authResponse.getRefreshToken());
            
            return ResponseEntity.ok(authResponse);
        } catch (AuthenticationServiceException e) {
            System.out.println("Login failed for user: " + authenticationRequest.getUsername() + " - " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    /**
     * Refresh JWT tokens using stateless IP validation
     * 
     * @param refreshTokenRequest Contains the refresh token
     * @param request HTTP request to extract current IP address
     * @return New JWT access token and refresh token
     */
    @PostMapping("/refresh_token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest,
                                          HttpServletRequest request) {
        try {
            // Extract current IP address for validation
            String currentIpAddress = request.getRemoteAddr();
            
            // Perform stateless token refresh with IP validation
            AuthenticationResponse authResponse = refreshTokenService.refresh(
                refreshTokenRequest.getRefreshToken(), 
                currentIpAddress
            );
            
            if (authResponse == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Refresh Token error. Please login again");
            }
            
            System.out.println("Token refresh successful");
            System.out.println("Current IP: " + currentIpAddress);
            System.out.println("New access token: " + authResponse.getAccessToken());
            System.out.println("New refresh token: " + authResponse.getRefreshToken());
            
            return ResponseEntity.ok(authResponse);
        } catch (Exception e) {
            System.out.println("Token refresh failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
}