package com.example.stage1.config;

import com.example.stage1.dto.AuthenticationRequest;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
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

    // Generate a JWT token for a user, first time login
    public String generateToken(UserDetails userDetails) {

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

}
