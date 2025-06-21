package com.example.stage4.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
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

    // Generate Access Token with IP address
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
                .claim("issuedBy", "learning JWT with Spring Security")
                .signWith(getKey())
                .compact();
    }

    // Generate Refresh Token with IP address
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
                .claim("issuedBy", "learning JWT with Spring Security")
                .signWith(getKey())
                .compact();
    }

    // Extract IP address from token
    public String extractIpAddress(String token) {
        return extractClaim(token, claims -> claims.get("ipAddress", String.class));
    }

    // Enhanced token validation with IP check
    public boolean validateToken(String token, UserDetails userDetails, String currentIpAddress) {
        try {
            String username = extractUsername(token);
            String tokenIpAddress = extractIpAddress(token);
            
            return (username.equals(userDetails.getUsername()) 
                    && !isTokenExpired(token)
                    && tokenIpAddress.equals(currentIpAddress));  // IP validation
        } catch (Exception e) {
            throw new RuntimeException("Token validation failed: " + e.getMessage());
        }
    }

    // Original validation method (for backward compatibility where IP check is not needed)
    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            String username = extractUsername(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            throw new RuntimeException("The token signature is invalid: " + e.getMessage());
        }
    }

    // Extract the username from a JWT token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String string, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(string);
        return claimsResolver.apply(claims);
    }

    // Extract all claims from a JWT token
    private Claims extractAllClaims(String token) {
        SecretKey secretKey = (SecretKey) getKey();
        return Jwts
                .parser()
                .verifyWith(secretKey)
                .build().parseSignedClaims(token).getPayload();
    }

    // Check if a JWT token is expired
    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date(System.currentTimeMillis()));
    }

    public Date extractExpiration(String token) {
        try {
            return extractClaim(token, Claims::getExpiration);
        } catch (Exception e) {
            System.out.println("Error extracting expiration date from token: " + e.getMessage());
            throw new RuntimeException("Failed to extract expiration date", e);
        }
    }
}