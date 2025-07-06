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
 * JwtAuthenticationFilter - Stage 4 Enhanced with Blacklist & IP Validation
 * 
 * This filter processes JWT tokens with the following security features:
 * - Token blocklist validation (prevents reuse of revoked tokens)
 * - IP address verification (tokens tied to originating IP)
 * - Strict authentication approach (requires valid token for protected endpoints)
 * - Comprehensive error handling with appropriate HTTP status codes
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;
    private final TokenBlacklistService tokenBlacklistService;

    /**
     * Determines if this filter should be skipped for certain endpoints.
     * Public endpoints that don't require JWT authentication are excluded.
     * 
     * @param request the HTTP request
     * @return true if the filter should be skipped, false otherwise
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        
        // FIXED: Use startsWith instead of equals to handle trailing slashes and sub-paths
        return path.startsWith("/api/login") || 
               path.startsWith("/api/refresh_token") ||
               path.startsWith("/api/register") ||
               path.startsWith("/api/public");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, 
                                    FilterChain filterChain)
            throws ServletException, IOException {
        
        System.out.println("Processing request: " + request.getRequestURI());
        System.out.println("Request method: " + request.getMethod());
        System.out.println("Client IP: " + request.getRemoteAddr());
        
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

        // FIXED: Strict approach - if no token is provided, return 401 Unauthorized
        // This only applies to protected endpoints (public endpoints are excluded by shouldNotFilter)
        if (token == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Missing authentication token");
            return;
        }

        try {
            // Step 1: Check if the token is blacklisted
            if (tokenBlacklistService.isBlacklisted(token)) {
                System.out.println("Rejected blacklisted token: " + token.substring(0, Math.min(token.length(), 20)) + "...");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Token is blacklisted");
                return;
            }

            // Step 2: Extract username and current IP address
            String username = jwtUtil.extractUsername(token);
            String currentIpAddress = request.getRemoteAddr();
            
            System.out.println("Processing token for user: " + username);
            System.out.println("Request from IP: " + currentIpAddress);
            
            // Step 3: Load user details using the extracted username
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

            // FIXED: Additional check - ensure userDetails is not null 
            // (CustomUserDetailsService should throw exception, but adding safety check)
            if (userDetails == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("User not found or account disabled");
                return;
            }

            // Step 4: Validate the token with IP address verification
            if (jwtUtil.validateToken(token, userDetails, currentIpAddress)) {
                System.out.println("Token validation successful with IP verification");
                
                // Create an authentication object and set it in the Security Context
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                System.out.println("Token validation failed - possible IP mismatch or token invalid");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Token validation failed - IP address mismatch or invalid token");
                return;
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