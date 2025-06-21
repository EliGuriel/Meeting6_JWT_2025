package com.example.stage5.config;

import com.example.stage5.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;


@Component
public class JwtUtil {


    private final Key key;  // Store the generated key in a field

//    public JwtUtil() {
//        try {
//            // private final String SECRET_KEY = JwtProperties.SECRET;
//            KeyGenerator secretKeyGen = KeyGenerator.getInstance("HmacSHA256");
//            this.key = Keys.hmacShaKeyFor(secretKeyGen.generateKey().getEncoded());
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        }
//
//    }

    // TODO 5: we added a constructor that takes the secret key as a parameter from the application.properties file
    public JwtUtil(@Value("${jwt.secret:defaultSecretThatIsAtLeast32BytesLong}") String secret) {
        // המרת המחרוזת הסודית למפתח
        byte[] keyBytes = secret.getBytes();
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }
    // A method to return the key as a Base64 encoded string
    public String getEncodedKey() {
        return Base64.getEncoder().encodeToString(this.key.getEncoded());
    }


    private Key getKey() {
        return this.key;  // Use the stored key
    }

    // Generate a JWT token for a user, first time login
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
                .signWith(getKey())
                .compact();
    }


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
                .signWith(getKey())
                .compact();
    }


    /*
    TODO stage2 added these methods
     */
    // Extract the expiration date from a JWT token, and implicitly validate the token
    // This implementation implicitly validates the signature when extracting claims:
    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            // extract the username from the JWT token
            String username = extractUsername(token);
            // If signature verification fails, extractUsername will throw an exception.

            // check if the username extracted from the JWT token matches the username in the UserDetails object
            // and the token is not expired
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            // Handle the invalid signature here
            throw new RuntimeException("The token signature is invalid: " + e.getMessage());
        }
        // Other exceptions related to token parsing can also be caught here if necessary
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
            // add error handling here
            System.out.println("Error extracting expiration date from token: " + e.getMessage());
            throw new RuntimeException("Failed to extract expiration date", e);
        }
    }


}
