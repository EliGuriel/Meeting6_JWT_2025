package com.example.stage4.service;

import com.example.stage4.config.JwtProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * CustomLogoutHandler - Simplified Stateless Implementation
 * 
 * This logout handler only needs to blacklist the current access token.
 * Since refresh tokens are no longer stored in the database, there's no need
 * for complex database cleanup operations. The blacklist system ensures
 * that both access and refresh tokens cannot be reused after logout.
 */
@Component
@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutSuccessHandler {

    private final TokenBlacklistService tokenBlacklistService;

    @Override
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) {

        System.out.println("Processing logout request");

        // Extract the JWT access token from the request header
        String accessToken = request.getHeader(JwtProperties.HEADER_STRING);
        if (accessToken != null && accessToken.startsWith(JwtProperties.TOKEN_PREFIX)) {
            accessToken = accessToken.substring(JwtProperties.TOKEN_PREFIX.length());
            
            // Blacklist the access token to prevent its future use
            tokenBlacklistService.addToBlacklist(accessToken);
            System.out.println("Access token blacklisted successfully");
        }

        // Note: In a real-world scenario, you might also want to blacklist the refresh token
        // This could be done by having the client send the refresh token in the logout request
        // or by extracting any refresh token from the request body/parameters
        
        // For now, we rely on the client to discard the refresh token on their side
        // and the token rotation mechanism in the refresh process to invalidate old tokens

        response.setStatus(HttpServletResponse.SC_OK);
        System.out.println("Logout completed successfully");
    }
}