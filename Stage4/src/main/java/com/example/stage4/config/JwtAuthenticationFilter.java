package com.example.stage4.config;

import com.example.stage4.service.TokenBlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import com.example.stage4.service.CustomUserDetailsService;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JwtAuthenticationFilter - Enhanced with IP Validation
 * 
 * This filter processes JWT tokens and validates them including IP address verification.
 * The IP validation ensures that tokens can only be used from the same IP address
 * where they were originally issued, adding an extra layer of security.
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;
    private final TokenBlacklistService tokenBlacklistService;

    // This method is used to check if the request should be filtered or not
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return path.equals("/api/login") || path.equals("/api/refresh_token");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        // Retrieve the Authorization header from the request
        String header = request.getHeader(JwtProperties.HEADER_STRING);
        String token;

        // Extract the token from the header if it's present
        if (header != null && header.startsWith(JwtProperties.TOKEN_PREFIX)) {
            token = header.substring(JwtProperties.TOKEN_PREFIX.length());
        } else {
            // Alternatively, try to get the token from a query parameter
            token = request.getParameter("token");
        }

        try {
            if (token != null) {
                // Check if the token is blacklisted
                if (tokenBlacklistService.isBlacklisted(token)) {
                    System.out.println("Rejected blacklisted token: " + token);
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Token is blacklisted");
                    return;
                }

                // Extract username and current IP address
                String username = jwtUtil.extractUsername(token);
                String currentIpAddress = request.getRemoteAddr();
                
                System.out.println("Processing token for user: " + username);
                System.out.println("Request from IP: " + currentIpAddress);
                
                // Load user details using the extracted username
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

                // Validate the token with IP address verification
                if (jwtUtil.validateToken(token, userDetails, currentIpAddress)) {
                    System.out.println("Token validation successful with IP verification");
                    
                    // Create an authentication object and set it in the Security Context
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else {
                    System.out.println("Token validation failed - possible IP mismatch");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Token validation failed - IP address mismatch");
                    return;
                }
            }
        } catch (UsernameNotFoundException | AuthenticationCredentialsNotFoundException ex) {
            System.out.println("Authentication error: " + ex.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(ex.getMessage());
            return;
        } catch (Exception ex) {
            System.out.println("Token processing error: " + ex.getMessage());
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("An error occurred while processing the token");
            return;
        }

        // Pass the request along the filter chain
        filterChain.doFilter(request, response);
    }
}