package com.example.stage5.service;

import com.example.stage5.config.JwtProperties;
import com.example.stage5.config.JwtUtil;
import com.example.stage5.entity.User;
import com.example.stage5.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * The CustomLogoutHandler class is responsible for handling actions when a user successfully logs out.
 * Specifically, it extracts the JWT from the request header, blacklists the token, and deletes the associated refresh token.
 * code flow:
 * +----------------------------------------+
 * |         CustomLogoutHandler            |
 * +----------------------------------------+
 * |
 * v
 * +----------------------------------------+
 * | onLogoutSuccess(HttpServletRequest,    |
 * | HttpServletResponse, Authentication)   |
 * +----------------------------------------+
 * |
 * v
 * +----------------------------------------+
 * | Extract JWT token from request header  |
 * +----------------------------------------+
 * |
 * v
 * +----------------------------------------+
 * | Is token present and valid (starts     |
 * | with TOKEN_PREFIX)?                    |
 * +----------------------------------------+
 * |                         |
 * | Yes                     | No
 * v                         v
 * +----------------------------------------+
 * | Trim TOKEN_PREFIX from token           |
 * +----------------------------------------+
 * |
 * v
 * +----------------------------------------+
 * | Blacklist the JWT token using          |
 * | tokenBlacklistService                  |
 * +----------------------------------------+
 * |
 * v
 * +----------------------------------------+
 * | Extract username from JWT token using  |
 * | jwtUtil                                |
 * +----------------------------------------+
 * |
 * v
 * +----------------------------------------+
 * | Find the user by username using        |
 * | userRepository                         |
 * +----------------------------------------+
 * |
 * v
 * +----------------------------------------+
 * | Is user found?                         |
 * +----------------------------------------+
 * |                         |
 * | Yes                     | No
 * v                         v
 * +----------------------------------------+
 * | Set user's refresh token to null       |
 * | (Triggers orphan removal)              |
 * +----------------------------------------+
 * |
 * v
 * +----------------------------------------+
 * | Save user to apply the changes         |
 * | (userRepository.save(user))            |
 * +----------------------------------------+
 * |
 * v
 * +----------------------------------------+
 * | Set response status to OK (200)        |
 * +----------------------------------------+
 */

// TODO stage4 - 1. Implement the CustomLogoutHandler class
@Component
@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutSuccessHandler {

    private final TokenBlacklistService tokenBlacklistService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    @Override
    @Transactional
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) {

        // Extract the JWT token from the request header
        String token = request.getHeader(JwtProperties.HEADER_STRING);
        if (token != null && token.startsWith(JwtProperties.TOKEN_PREFIX)) {
            token = token.substring(JwtProperties.TOKEN_PREFIX.length());
        } else {
            // disconnect from the front end only, there was no token, or it was not in the correct format ...
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        // add the token to the blacklist
        tokenBlacklistService.addToBlacklist(token);

        // Check if there is a refreshToken parameter in the request
        String refreshToken = request.getParameter("refreshToken");
        if (refreshToken != null && !refreshToken.isEmpty()) {
            // Add the refresh token to the blacklist
            tokenBlacklistService.addToBlacklist(refreshToken);
        }

        response.setStatus(HttpServletResponse.SC_OK);
    }
}
