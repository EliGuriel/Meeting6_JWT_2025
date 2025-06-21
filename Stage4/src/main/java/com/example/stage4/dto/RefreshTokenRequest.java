package com.example.stage4.dto;

import lombok.Data;

/*
    * The RefreshTokenRequest class is used to store the refresh token
    * It is used in the authentication controller for refresh the JWT
 */
@Data
public class RefreshTokenRequest {
    private String refreshToken;
}
