package com.example.stage4.service;

import com.example.stage4.config.JwtUtil;
import com.example.stage4.dto.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * RefreshTokenService - Stage 4 Enhanced Stateless Implementation
 * 
 * This service handles token refresh operations with enhanced security features:
 * - Token blacklist validation to prevent reuse of revoked tokens
 * - IP address validation using claims embedded in JWT tokens
 * - Token rotation for enhanced security (old tokens are blacklisted)
 * - Comprehensive error handling with proper exception management
 * - Fully stateless - no database dependencies for token validation
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;

    /**
     * Refresh JWT tokens with comprehensive security validations
     * 
     * @param refreshToken The current refresh token
     * @param currentIpAddress The IP address of the current request
     * @return AuthenticationResponse with new access and refresh tokens
     * @throws RuntimeException for various validation failures
     */
    public AuthenticationResponse refresh(String refreshToken, String currentIpAddress) {
        System.out.println("=== Token Refresh Process Started ===");
        System.out.println("Current IP address: " + currentIpAddress);
        
        try {
            // Step 1: Validate refresh token is not blocklisted
            if (tokenBlacklistService.isBlacklisted(refreshToken)) {
                System.out.println("Refresh token is blacklisted - potential security threat");
                throw new RuntimeException("Refresh token is blacklisted. Please login again.");
            }
            System.out.println("✓ Refresh token is not blacklisted");

            // Step 2: Validate refresh token is not expired
            if (jwtUtil.isTokenExpired(refreshToken)) {
                System.out.println("Refresh token has expired");
                throw new RuntimeException("Refresh token has expired. Please login again.");
            }
            System.out.println("✓ Refresh token is not expired");

            // Step 3: Extract data from refresh token
            String username = jwtUtil.extractUsername(refreshToken);
            String tokenIpAddress = jwtUtil.extractIpAddress(refreshToken);
            
            System.out.println("Token username: " + username);
            System.out.println("Token IP address: " + tokenIpAddress);

            // Step 4: Validate IP address matches (security check)
            if (!tokenIpAddress.equals(currentIpAddress)) {
                System.out.println("IP mismatch detected - potential security threat");
                System.out.println("Token IP: " + tokenIpAddress + ", Request IP: " + currentIpAddress);
                throw new RuntimeException("Invalid refresh token: IP address mismatch. Please login again for security reasons.");
            }
            System.out.println("✓ IP address validation passed");

            // Step 5: Load user details to ensure user still exists and is valid
            UserDetails userDetails;
            try {
                userDetails = customUserDetailsService.loadUserByUsername(username);
                System.out.println("✓ User details loaded successfully for: " + username);
            } catch (UsernameNotFoundException e) {
                System.out.println("User not found during refresh: " + username);
                throw new RuntimeException("User not found: " + username + ". Please login again.");
            }

            // Step 6: Blocklist the old refresh token (token rotation for security)
            tokenBlacklistService.addToBlacklist(refreshToken);
            System.out.println("✓ Old refresh token blacklisted for security (token rotation)");

            // Step 7: Generate a new token pair with the same IP address
            String newAccessToken = jwtUtil.generateAccessToken(userDetails, currentIpAddress);
            String newRefreshToken = jwtUtil.generateRefreshToken(userDetails, currentIpAddress);

            System.out.println("✓ New tokens generated successfully");
            System.out.println("New access token length: " + newAccessToken.length());
            System.out.println("New refresh token length: " + newRefreshToken.length());
            System.out.println("=== Token Refresh Process Completed Successfully ===");

            return new AuthenticationResponse(newAccessToken, newRefreshToken);
            
        } catch (RuntimeException e) {
            // Re-throw runtime exceptions with additional context
            System.out.println("Token refresh failed: " + e.getMessage());
            throw e;
        } catch (Exception e) {
            // Handle any unexpected technical errors
            System.out.println("Technical error during token refresh: " + e.getMessage());
            throw new RuntimeException("Technical error during token refresh. Please try again or login.", e);
        }
    }
}