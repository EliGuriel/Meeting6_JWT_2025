package com.example.stage3.service;

import com.example.stage3.config.JwtUtil;
import com.example.stage3.dto.AuthenticationRequest;
import com.example.stage3.dto.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    /*
     The authenticate() method takes in an AuthenticationRequest object,
     which contains the username and password.
     The method returns an AuthenticationResponse object,
     which contains the JWT and refresh token, and the user's roles.

     */
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        // load the user details from the database using the username by calling the loadUserByUsername() method
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());

        // check if the password matches the password in the database
        if (!passwordEncoder.matches(authenticationRequest.getPassword(), userDetails.getPassword())) {
            throw new AuthenticationServiceException("Invalid credentials");
        }

        // generate the JWT token
        String jwtToken = jwtUtil.generateAccessToken(userDetails);
        // generate the refresh token
        String refreshToken = jwtUtil.generateRefreshToken(userDetails);

        // get the user's roles
        Collection<? extends GrantedAuthority> roles = userDetails.getAuthorities();

        // return the AuthenticationResponse object
        return new AuthenticationResponse(jwtToken, refreshToken);
    }
}

