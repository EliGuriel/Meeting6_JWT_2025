package com.example.stage4.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * JwtUtil - Stage 4 Enhanced JWT Utilities with IP Validation
 * 
 * This utility class handles JWT token operations with enhanced security features:
 * - IP address embedded in token claims for enhanced security
 * - Strict error handling that distinguishes between validation failures and technical errors
 * - Support for both access and refresh tokens with IP validation
 * - Backward compatibility with non-IP validation methods
 */
@Component
public class JwtUtil {

    private final Key key;  // Store the generated key in a field

    public JwtUtil() {
        try {
            KeyGenerator secretKeyGen = KeyGenerator.getInstance("HmacSHA256");
            this.key = Keys.hmacShaKeyFor(secretKeyGen.generateKey().getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private Key getKey() {
        return this.key;  // Use the stored key
    }

    /**
     * Generate Access Token with IP address embedded as claim
     * 
     * @param userDetails User details containing username and authorities
     * @param ipAddress IP address to embed in the token
     * @return JWT access token string
     */
    public String generateAccessToken(UserDetails userDetails, String ipAddress) {
        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .and()
                .claim("roles", userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .claim("ipAddress", ipAddress)  // IP claim for security
                .claim("tokenType", "access")   // Token type for clarity
                .claim("issuedBy", "learning JWT with Spring Security")
                .signWith(getKey())
                .compact();
    }

    /**
     * Generate Refresh Token with IP address embedded as claim
     * 
     * @param userDetails User details containing username
     * @param ipAddress IP address to embed in the token
     * @return JWT refresh token string
     */
    public String generateRefreshToken(UserDetails userDetails, String ipAddress) {
        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + JwtProperties.REFRESH_EXPIRATION_TIME))
                .and()
                .claim("ipAddress", ipAddress)  // IP claim for security
                .claim("tokenType", "refresh")  // Token type for clarity
                .claim("issuedBy", "learning JWT with Spring Security")
                .signWith(getKey())
                .compact();
    }

    /**
     * Extract IP address from token claims
     * 
     * @param token JWT token string
     * @return IP address embedded in the token
     */
    public String extractIpAddress(String token) {
        return extractClaim(token, claims -> claims.get("ipAddress", String.class));
    }

    /**
     * Enhanced token validation with IP address verification
     * This is the primary validation method for Stage 4
     * 
     * @param token JWT token to validate
     * @param userDetails User details to validate against
     * @param currentIpAddress Current request IP address
     * @return true if token is valid and IP matches, false otherwise
     */
    public boolean validateToken(String token, UserDetails userDetails, String currentIpAddress) {
        try {
            String username = extractUsername(token);
            String tokenIpAddress = extractIpAddress(token);
            
            // Comprehensive validation: username, expiration, and IP address
            return (username.equals(userDetails.getUsername()) 
                    && !isTokenExpired(token)
                    && tokenIpAddress.equals(currentIpAddress));
        } catch (ExpiredJwtException e) {
            System.out.println("Token validation failed: Token expired");
            return false;  // Token expired - return false instead of throwing
        } catch (SignatureException e) {
            System.out.println("Token validation failed: Invalid signature");
            return false;  // Invalid signature - return false instead of throwing  
        } catch (MalformedJwtException e) {
            System.out.println("Token validation failed: Malformed token");
            return false;  // Malformed token - return false instead of throwing
        } catch (Exception e) {
            // Any other exception is considered a technical error
            throw new RuntimeException("Technical error during token validation: " + e.getMessage(), e);
        }
    }

    /**
     * Basic token validation without IP check (for backward compatibility)
     * 
     * @param token JWT token to validate
     * @param userDetails User details to validate against
     * @return true if token is valid, false otherwise
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            String username = extractUsername(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (ExpiredJwtException e) {
            System.out.println("Token validation failed: Token expired");
            return false;  // Token expired - return false instead of throwing
        } catch (SignatureException e) {
            System.out.println("Token validation failed: Invalid signature");
            return false;  // Invalid signature - return false instead of throwing  
        } catch (MalformedJwtException e) {
            System.out.println("Token validation failed: Malformed token");
            return false;  // Malformed token - return false instead of throwing
        } catch (Exception e) {
            // Any other exception is considered a technical error
            throw new RuntimeException("Technical error during token validation: " + e.getMessage(), e);
        }
    }

    /**
     * Extract the username from a JWT token
     * 
     * @param token JWT token string
     * @return Username from a token subject
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Generic method to extract any claim from token
     * 
     * @param token JWT token string
     * @param claimsResolver Function to resolve specific claim
     * @return Extracted claim value
     */
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract all claims from a JWT token
     * This method can throw JWT-related exceptions that should be handled by validation methods
     * 
     * @param token JWT token string
     * @return Claims object containing all token claims
     */
    private Claims extractAllClaims(String token) {
        SecretKey secretKey = (SecretKey) getKey();
        return Jwts
                .parser()
                .verifyWith(secretKey)
                .build().parseSignedClaims(token).getPayload();
    }

    /**
     * Check if a JWT token is expired
     * 
     * @param token JWT token string
     * @return true if token is expired, false otherwise
     */
    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date(System.currentTimeMillis()));
    }

    /**
     * Extract the expiration date from a JWT token
     * 
     * @param token JWT token string
     * @return Expiration date of the token
     */
    public Date extractExpiration(String token) {
        try {
            return extractClaim(token, Claims::getExpiration);
        } catch (Exception e) {
            System.out.println("Error extracting expiration date from token: " + e.getMessage());
            throw new RuntimeException("Failed to extract expiration date", e);
        }
    }
}