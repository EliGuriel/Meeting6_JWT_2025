package com.example.stage2.config;

/*
    * This class is responsible for filtering the incoming requests and checking for the presence of a JWT token.
    * The JwtAuthenticationFilter class is a custom filter for handling JWT (JSON Web Token)
    * based authentication in a Spring Boot application. It extends OncePerRequestFilter,
    * which ensures the filter is executed once per request. This class is responsible for:
        Retrieving the JWT Token: It looks for the token in the Authorization header or as a query parameter.
        Extracting the Username from the JWT: It uses the provided JwtUtil to extract the username
        * embedded in the token.
        Loading User Details: It uses the CustomUserDetailsService to load user details
        * (e.g., roles, authorities) from the username.
        Validating the JWT Token: It validates the token to ensure it is legitimate and not expired.
        Setting Authentication in Security Context: If the token is valid,
        * it sets up the authentication in the SecurityContextHolder so that the user is considered
        * authenticated in the current request context.
    Detailed Explanation:
        Annotations:
            @RequiredArgsConstructor: Generates a constructor with required arguments to autowire dependencies
            (JwtUtil and CustomUserDetailsService).
        Dependencies:
            JwtUtil: Utility class for handling JWT operations such as token generation, validation,
            and extraction of claims.
        CustomUserDetailsService: Service to load user-specific data (implementing UserDetailsService).
            Filter Logic — doFilterInternal:
            Retrieve the Token: The method checks the Authorization header or query parameter for a token.
    flow:


    TODO Stage 2: Implement the JwtAuthenticationFilter class
 */
import com.example.stage2.service.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{

    final private JwtUtil jwtUtil;
    final private CustomUserDetailsService customUserDetailsService;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return path.startsWith("/api/login") ||
                path.startsWith("/api/register") ||
                path.startsWith("/api/public");
    }


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        // Log the request details
        System.out.println("Incoming Request: " + request.getRequestURI());
        System.out.println("Request Method: " + request.getMethod());
        System.out.println("Request URL: " + request.getRequestURL());

        // retrieve the Authorization header from the request
        String header = request.getHeader(JwtProperties.HEADER_STRING);
        String token;

        // extract the token from the header if it's present
        // this is when sending the token in the Authorization header
        if (header != null && header.startsWith(JwtProperties.TOKEN_PREFIX)) {
            token = header.substring(JwtProperties.TOKEN_PREFIX.length());
        } else
        // if the header is not present or does not start with the TOKEN_PREFIX,
        // we will try to get the token from a query parameter
        {
            // alternatively, try to get the token from a query parameter
            token = request.getParameter("token");
        }

        // Strict approach: if no token is provided, return 401 Unauthorized
        if (token == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Missing authentication token");
            return;
        }

        try {
            // extract the username from the token
            String username = jwtUtil.extractUsername(token);
            // load user details using the extracted username
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

            // validate the token with the loaded user details
            if (jwtUtil.validateToken(token, userDetails)) {
                // create an authentication object and set it in the Security Context
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                // set the authentication in the SecurityContextHolder
                /*
                This is like preforming a login operation,
                where the user is authenticated and their details are stored in the SecurityContext.
                 */
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                // If token validation fails, return 401 Unauthorized
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid or expired token");
                return;
            }
        } catch (UsernameNotFoundException | AuthenticationCredentialsNotFoundException ex) {
            // Return 401 Unauthorized for invalid credentials
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(ex.getMessage());
            return;
            // any other exception, such as token expiration or invalid signature,
        } catch (Exception ex) {
            // For other exceptions, return 500 Internal Server Error
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("An error occurred while processing the token");
            return;
        }

        // pass the request along the filter chain
        filterChain.doFilter(request, response);

    }
}