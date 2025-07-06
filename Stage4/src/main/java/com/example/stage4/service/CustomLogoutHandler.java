package com.example.stage4.service;

import com.example.stage4.config.JwtProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * CustomLogoutHandler - Stage 4 Enhanced Stateless Implementation
 * <p>
 * This logout handler implements a stateless logout mechanism using token blocklisting.
 * Key features:
 * - Blacklists the current access token to prevent future use
 * - No database cleanup required (stateless architecture)
 * - Handles multiple token sources (header and query parameter)
 * - Comprehensive error handling and logging
 * - Client is responsible for discarding refresh tokens
 */
@Component
@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutSuccessHandler {

    private final TokenBlacklistService tokenBlacklistService;

    /**
     * Handle successful logout by blocklisting the access token
     * 
     * @param request HTTP request containing the JWT token
     * @param response HTTP response to be sent to a client
     * @param authentication Authentication object (maybe null)
     */
    @Override
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) {

        System.out.println("=== Logout Process Started ===");
        System.out.println("Request URI: " + request.getRequestURI());
        System.out.println("Client IP: " + request.getRemoteAddr());

        try {
            String accessToken = extractTokenFromRequest(request);
            
            if (accessToken != null && !accessToken.trim().isEmpty()) {
                // Blocklist the access token to prevent its future use
                tokenBlacklistService.addToBlacklist(accessToken);
                System.out.println("✓ Access token blacklisted successfully");
                System.out.println("✓ Token length: " + accessToken.length());
                
                // Set successful response
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType("application/json");
                response.getWriter().write("{\"message\":\"Logout successful\"}");
                
                System.out.println("=== Logout Process Completed Successfully ===");
            } else {
                System.out.println("⚠ No access token found in request");
                // Still consider it a successful logout
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType("application/json");
                response.getWriter().write("{\"message\":\"Logout completed (no token found)\"}");
            }
            
        } catch (Exception e) {
            System.out.println("Error during logout process: " + e.getMessage());
            try {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"Logout process failed\"}");
            } catch (IOException ioException) {
                System.out.println("Failed to write error response: " + ioException.getMessage());
            }
        }

        // Note: In the stateless approach:
        // 1. We only blocklist the access token from request
        // 2. Client is responsible for discarding refresh token
        // 3. Token rotation mechanism in refresh process handles old token invalidation
        // 4. No database cleanup is required since no refresh tokens are stored
        
        System.out.println("Logout process completed");
    }
    
    /**
     * Extract JWT token from HTTP request
     * Supports both Authorization header and query parameter
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        // First, try to get token from Authorization header
        String header = request.getHeader(JwtProperties.HEADER_STRING);
        if (header != null && header.startsWith(JwtProperties.TOKEN_PREFIX)) {
            String token = header.substring(JwtProperties.TOKEN_PREFIX.length());
            System.out.println("✓ Token found in Authorization header");
            return token;
        }
        
        // Alternatively, try to get a token from query parameter
        String queryToken = request.getParameter("token");
        if (queryToken != null && !queryToken.trim().isEmpty()) {
            System.out.println("✓ Token found in query parameter");
            return queryToken;
        }
        
        System.out.println("⚠ No token found in request (neither header nor query parameter)");
        return null;
    }
}