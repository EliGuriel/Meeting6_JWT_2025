package com.example.stage3.service;


import com.example.stage3.config.JwtUtil;
import com.example.stage3.dto.AuthenticationResponse;
import com.example.stage3.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    final private UserRepository userRepository;
    final private CustomUserDetailsService customUserDetailsService;
    final private JwtUtil jwtUtil;


    // this should be called when the user requests a new JWT token and new Refresh token, using the current refresh token
    public AuthenticationResponse refreshTokens(String refreshToken) {

        // if it is not valid, throw an exception or handle accordingly
        if (jwtUtil.isTokenExpired(refreshToken)) {
            System.out.println("Refresh Token has expired. Please login again");
            return null;
        }

        // if it is valid, find the user by username
        String username = jwtUtil.extractUsername(refreshToken);
        // userDetailsService.loadUserByUsername() method is called to load the user details
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
        // generate a new JWT token from the username
        String newJwtToken = jwtUtil.generateAccessToken(userDetails);
        // create a new refresh token for the user
     //   RefreshToken newRefreshToken = createRefreshToken(username);
        String newRefreshToken = jwtUtil.generateRefreshToken(userDetails);
        // return the new JWT token and the new refresh token
        return new AuthenticationResponse(newJwtToken, newRefreshToken);
    }
}

