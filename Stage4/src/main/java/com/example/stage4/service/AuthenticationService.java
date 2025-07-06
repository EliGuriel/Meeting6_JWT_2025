package com.example.stage4.service;

import com.example.stage4.config.JwtUtil;
import com.example.stage4.dto.AuthenticationRequest;
import com.example.stage4.dto.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * AuthenticationService - Stage 4 Enhanced Stateless Implementation
 * <p>
 * This service handles user authentication with advanced security features:
 * - Stateless JWT token generation with embedded IP addresses
 * - Token blocklist validation for enhanced security
 * - Comprehensive error handling and logging
 * - IP-based token binding for additional security layer
 * - Full validation pipeline with proper exception management
 */
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final TokenBlacklistService tokenBlacklistService;

    /**
     * Authenticate user and generate JWT tokens with IP binding
     * 
     * @param authenticationRequest Contains username and password
     * @param ipAddress Client IP address to embed in tokens
     * @return AuthenticationResponse with access and refresh tokens
     * @throws AuthenticationServiceException for authentication failures
     */
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest, String ipAddress) {
        System.out.println("=== Authentication Process Started ===");
        System.out.println("Username: " + authenticationRequest.getUsername());
        System.out.println("Client IP: " + ipAddress);
        
        try {
            // Step 1: Load user details from a database
            UserDetails userDetails;
            try {
                userDetails = customUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());
                System.out.println("✓ User details loaded successfully");
            } catch (UsernameNotFoundException e) {
                System.out.println("User not found: " + authenticationRequest.getUsername());
                throw new AuthenticationServiceException("Invalid credentials");
            } catch (Exception e) {
                System.out.println("Error loading user details: " + e.getMessage());
                throw new AuthenticationServiceException("Authentication failed");
            }
            
            // Step 2: Validate credentials
            try {
                validateCredentials(authenticationRequest.getPassword(), userDetails.getPassword());
                System.out.println("✓ Password validation successful");
            } catch (AuthenticationServiceException e) {
                System.out.println("Password validation failed for user: " + authenticationRequest.getUsername());
                throw e; // Re-throw authentication service exception
            }

            // Step 3: Generate both tokens with IP address embedded as claims
            String accessToken = jwtUtil.generateAccessToken(userDetails, ipAddress);
            String refreshToken = jwtUtil.generateRefreshToken(userDetails, ipAddress);
            
            System.out.println("✓ Tokens generated successfully");
            System.out.println("Access token length: " + accessToken.length());
            System.out.println("Refresh token length: " + refreshToken.length());
            
            // Step 4: Ensure tokens are not blocklisted (security check)
            try {
                validateTokenNotBlacklisted(accessToken);
                validateTokenNotBlacklisted(refreshToken);
                System.out.println("✓ Token blacklist validation passed");
            } catch (AuthenticationServiceException e) {
                System.out.println("Token blacklist validation failed");
                throw e;
            }
            
            System.out.println("✓ User authenticated successfully: " + authenticationRequest.getUsername());
            System.out.println("✓ IP address embedded in tokens: " + ipAddress);
            System.out.println("=== Authentication Process Completed Successfully ===");
            
            return new AuthenticationResponse(accessToken, refreshToken);
            
        } catch (AuthenticationServiceException e) {
            // Re-throw authentication service exceptions
            System.out.println("Authentication failed: " + e.getMessage());
            throw e;
        } catch (Exception e) {
            // Handle any unexpected technical errors
            System.out.println("Technical error during authentication: " + e.getMessage());
            throw new AuthenticationServiceException("Authentication failed due to technical error");
        }
    }

    /**
     * Validate user credentials (password check)
     * 
     * @param rawPassword Plain text password from request
     * @param encodedPassword Encoded password from a database
     * @throws AuthenticationServiceException if passwords don't match
     */
    private void validateCredentials(String rawPassword, String encodedPassword) {
        if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new AuthenticationServiceException("Invalid credentials");
        }
    }

    /**
     * Validate that token is not in the blocklist
     * 
     * @param token JWT token to validate
     * @throws AuthenticationServiceException if token is blocklisted
     */
    private void validateTokenNotBlacklisted(String token) {
        if (tokenBlacklistService.isBlacklisted(token)) {
            throw new AuthenticationServiceException("Token is blacklisted");
        }
    }
}