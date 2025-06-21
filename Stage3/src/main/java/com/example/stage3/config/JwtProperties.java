package com.example.stage3.config;

public class JwtProperties {

    // The EXPIRATION_TIME constant is used to set the expiration time of the JWT
    // 5 minutes, it is recommended to set this to 30 minutes
    public static final long EXPIRATION_TIME = 300_000; // 5 minutes

    /* TODO : Stage 2 added this constant: TOKEN_PREFIX and HEADER_STRING */
    // The TOKEN_PREFIX constant is used to prefix the JWT in the Authorization header
    public static final String TOKEN_PREFIX = "Bearer ";

    // The HEADER_STRING constant is used to set the key of the Authorization header
    public static final String HEADER_STRING = "Authorization";
    // 5 minutes, it is recommended to set this to 20 minutes

    /* TODO: Stage 3 adding JWT refresh token properties */
    // IDLE_TIME is the time after which the refresh token expires if the user is idle
    public static final long IDLE_TIME = 300_000; // 5 minutes
    // REFRESH_EXPIRATION_TIME is the time after which the refresh token expires
    public static final long REFRESH_EXPIRATION_TIME = EXPIRATION_TIME + IDLE_TIME; // 10 minutes

}
