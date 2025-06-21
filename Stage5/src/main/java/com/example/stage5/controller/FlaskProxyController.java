package com.example.stage5.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.util.AntPathMatcher;

import jakarta.servlet.http.HttpServletRequest;

/*
    TODO Stage 5: Create a controller to proxy requests to the Flask server
 */

@RestController
@RequestMapping("/api/flask")
@RequiredArgsConstructor
public class FlaskProxyController {

    @Value("${flask.server.url}")
    private String flaskServerUrl;

    @Value("${flask.server.secret}")
    private String flaskServerSecret;

    private final RestTemplate restTemplate;

    @PreAuthorize("isAuthenticated()")  // רק בדיקה שהמשתמש מאומת
    @RequestMapping("/**")
    public ResponseEntity<String> proxyToFlask(HttpServletRequest request) {
        // הוסף יותר לוגים לניפוי שגיאות
        System.out.println("Proxy request received for path: " + request.getRequestURI());

        // לקבל את הנתיב היחסי מהבקשה
        String path = (String) request.getAttribute(HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE);
        String bestMatchPattern = (String) request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
        String finalPath = new AntPathMatcher().extractPathWithinPattern(bestMatchPattern, path);

        System.out.println("Final path for Flask: " + finalPath);

        // בניית ה-URL לשרת ה-Flask
        String flaskUrl = flaskServerUrl + "/" + finalPath;
        System.out.println("Forwarding to: " + flaskUrl);

        // יצירת HttpHeaders
        HttpHeaders headers = new HttpHeaders();

        // העברת נתוני המשתמש והתפקידים
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        headers.set("X-User", auth.getName());
        headers.set("X-User-Roles", auth.getAuthorities().toString());
        headers.set("Internal-Auth-Token", flaskServerSecret);

        // יצירת בקשה חדשה
        HttpEntity<Object> entity = new HttpEntity<>(headers);

        try {
            // ביצוע הבקשה לשרת ה-Flask
            ResponseEntity<String> response = restTemplate.exchange(
                    flaskUrl,
                    HttpMethod.valueOf(request.getMethod()),
                    entity,
                    String.class
            );

            System.out.println("Response status from Flask: " + response.getStatusCode());
            return response;
        } catch (Exception e) {
            System.err.println("Error forwarding request to Flask: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error forwarding request: " + e.getMessage());
        }
    }
}