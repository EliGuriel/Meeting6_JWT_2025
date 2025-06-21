package com.example.stage4.service;

import com.example.stage4.config.JwtUtil;
import com.example.stage4.dto.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

/**
 * RefreshTokenService - Stateless Implementation
 * 
 * This service handles token refresh operations without database dependencies.
 * All validation is performed using data embedded in the JWT tokens themselves,
 * including IP address validation for enhanced security.
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;

    public AuthenticationResponse refresh(String refreshToken, String currentIpAddress) {
        System.out.println("Processing token refresh request");
        System.out.println("Current IP address: " + currentIpAddress);
        
        // Step 1: Validate refresh token is not blacklisted
        if (tokenBlacklistService.isBlacklisted(refreshToken)) {
            throw new RuntimeException("Refresh token is blacklisted. Please login again.");
        }

        // Step 2: Validate refresh token is not expired
        if (jwtUtil.isTokenExpired(refreshToken)) {
            throw new RuntimeException("Refresh token has expired. Please login again.");
        }

        // Step 3: Extract data from refresh token
        String username = jwtUtil.extractUsername(refreshToken);
        String tokenIpAddress = jwtUtil.extractIpAddress(refreshToken);
        
        System.out.println("Token username: " + username);
        System.out.println("Token IP address: " + tokenIpAddress);

        // Step 4: Validate IP address matches
        if (!tokenIpAddress.equals(currentIpAddress)) {
            System.out.println("IP mismatch detected - potential security threat");
            throw new RuntimeException("Invalid refresh token: IP address mismatch. Token issued for: " 
                    + tokenIpAddress + ", current request from: " + currentIpAddress);
        }

        // Step 5: Load user details to ensure user still exists and is valid
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
        if (userDetails == null) {
            throw new RuntimeException("User not found: " + username);
        }

        // Step 6: Blacklist the old refresh token (token rotation for security)
        tokenBlacklistService.addToBlacklist(refreshToken);
        System.out.println("Old refresh token blacklisted for security");

        // Step 7: Generate new token pair with same IP address
        String newAccessToken = jwtUtil.generateAccessToken(userDetails, currentIpAddress);
        String newRefreshToken = jwtUtil.generateRefreshToken(userDetails, currentIpAddress);

        System.out.println("New tokens generated successfully");
        System.out.println("New access token: " + newAccessToken);
        System.out.println("New refresh token: " + newRefreshToken);

        return new AuthenticationResponse(newAccessToken, newRefreshToken);
    }
}