package com.example.stage5.config;

import com.example.stage5.service.CustomLogoutHandler;
import com.example.stage5.service.CustomUserDetailsService;
import com.example.stage5.service.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    /*
        TODO Stage 2: add JwtUtil and CustomUserDetailsService as dependencies
     */
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;
    private final CustomLogoutHandler customLogoutHandler;
    private final TokenBlacklistService tokenBlacklistService;

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // TODO 5: Add RestTemplate bean, used for making HTTP requests
    @Configuration
    public class AppConfig {

        @Bean
        public RestTemplate restTemplate() {
            return new RestTemplate();
        }
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // we don't need csrf protection in jwt
        http
                .csrf(AbstractHttpConfigurer::disable)
                // add cors corsConfigurer
                .cors(cors -> {
                    // register cors configuration source, React app is running on localhost:3000
                    cors.configurationSource(request -> {
                        var corsConfig = new CorsConfiguration();
                        corsConfig.setAllowedOrigins(List.of("http://localhost:5173")); // vite dev server
                        corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                        corsConfig.setAllowedHeaders(List.of("*"));
                        corsConfig.setAllowCredentials(true);
                        return corsConfig;
                    });
                })

                /*
                    TODO Stage 2: Authentication filter for JWT token
                 */
                // adding a custom JWT authentication filter
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtil, userDetailsService, tokenBlacklistService),
                        UsernamePasswordAuthenticationFilter.class)

                // The SessionCreationPolicy.STATELESS setting means that the application will not create or use HTTP sessions.
                // This is a common configuration in RESTful APIs, especially when using token-based authentication like JWT (JSON Web Token).
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Configuring authorization for HTTP requests
                .authorizeHttpRequests(auth -> auth
                        // TODO: Stage 3 added refresh_token to permitAll
                        .requestMatchers("/api/login/**", "/api/refresh_token/**").permitAll()

                        /*
                        TODO Stage 2: Authorization Rules Based on Roles
                         */
                        .requestMatchers("/api/home/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/api/protected-message/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/api/flask/**").hasAnyRole("USER", "ADMIN")

                        .anyRequest().authenticated())

                // TODO Stage 4: Add logout configuration
                .logout(logout -> logout
                        .logoutUrl("/api/logout")
                        .logoutSuccessHandler(customLogoutHandler)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .clearAuthentication(true)
                        .permitAll());

        return http.build();
    }

}
