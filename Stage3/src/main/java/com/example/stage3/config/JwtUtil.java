package com.example.stage3.config;

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


@Component
public class JwtUtil {

    private final Key key;  // Store the generated key in a field

    public JwtUtil() {
        try {
            // private final String SECRET_KEY = JwtProperties.SECRET;
            KeyGenerator secretKeyGen = KeyGenerator.getInstance("HmacSHA256");
            this.key = Keys.hmacShaKeyFor(secretKeyGen.generateKey().getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    private Key getKey() {
        return this.key;  // Use the stored key
    }

    // Generate a JWT Access Token for a user (short-lived: 5 minutes)
    public String generateAccessToken(UserDetails userDetails) {

        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .and()
                .claim("roles", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .claim("issuedBy", "learning JWT with Spring Security")
                .claim("tokenType", "access")  // Added token type for clarity
                .signWith(getKey())
                .compact();
    }

    // Generate a JWT Refresh Token for a user (longer-lived: 10 minutes)
    public String generateRefreshToken(UserDetails userDetails) {

        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + JwtProperties.REFRESH_EXPIRATION_TIME))
                .and()
                .claim("issuedBy", "learning JWT with Spring Security")
                .claim("tokenType", "refresh")  // Added token type for clarity
                .signWith(getKey())
                .compact();
    }

    /*
    TODO stage2 added these methods
    TODO stage3 updated validateToken with strict error handling
     */
    // Validate JWT token with strict error handling (returns false for invalid tokens instead of throwing exceptions)
    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            // extract the username from the JWT token
            String username = extractUsername(token);
            
            // check if the username extracted from the JWT token matches the username in the UserDetails object
            // and the token is not expired
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (ExpiredJwtException e) {
            // The Token is expired - this is not a technical error, just invalid token
            return false;
        } catch (SignatureException e) {
            // Invalid signature - this is not a technical error, just invalid token  
            return false;
        } catch (MalformedJwtException e) {
            // Malformed token - this is not a technical error, just invalid token
            return false;
        } catch (Exception e) {
            // Any other exception is considered a technical error
            throw new RuntimeException("Technical error while processing token: " + e.getMessage(), e);
        }
    }

    // Extract the username from a JWT token
    // This method can throw exceptions that should be handled by the caller
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String string, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(string);
        return claimsResolver.apply(claims);
    }

    // Extract all claims from a JWT token
    // This method can throw JWT-related exceptions that should be handled by validateToken or caller
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

    // Extract the expiration date from a JWT token
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}