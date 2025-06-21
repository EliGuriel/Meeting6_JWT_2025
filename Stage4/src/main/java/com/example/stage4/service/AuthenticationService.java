package com.example.stage4.service;

import com.example.stage4.config.JwtUtil;
import com.example.stage4.dto.AuthenticationRequest;
import com.example.stage4.dto.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * AuthenticationService - Stateless JWT Authentication
 * 
 * This service handles user authentication and generates JWT tokens with embedded IP addresses.
 * The new implementation is fully stateless - no database storage for refresh tokens.
 * IP validation is performed using claims embedded directly in the JWT tokens.
 */
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final TokenBlacklistService tokenBlacklistService;

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest, String ipAddress) {
        // Load user details from database
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        
        // Validate credentials
        validateCredentials(authenticationRequest.getPassword(), userDetails.getPassword());

        // Generate both tokens with IP address embedded as claims
        String accessToken = jwtUtil.generateAccessToken(userDetails, ipAddress);
        String refreshToken = jwtUtil.generateRefreshToken(userDetails, ipAddress);
        
        // Ensure tokens are not blacklisted (security check)
        validateTokenNotBlacklisted(accessToken);
        
        System.out.println("User authenticated: " + authenticationRequest.getUsername());
        System.out.println("IP address embedded in tokens: " + ipAddress);
        System.out.println("Access token generated: " + accessToken);
        System.out.println("Refresh token generated: " + refreshToken);
        
        return new AuthenticationResponse(accessToken, refreshToken);
    }

    private void validateCredentials(String rawPassword, String encodedPassword) {
        if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new AuthenticationServiceException("Invalid credentials");
        }
    }

    private void validateTokenNotBlacklisted(String token) {
        if (tokenBlacklistService.isBlacklisted(token)) {
            throw new AuthenticationServiceException("Token is blacklisted");
        }
    }
}