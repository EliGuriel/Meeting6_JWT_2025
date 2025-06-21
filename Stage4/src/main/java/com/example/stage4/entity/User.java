package com.example.stage4.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/**
 * User Entity - Simplified without RefreshToken relationship
 * 
 * This entity has been simplified since refresh tokens are no longer stored
 * in the database. All token-related information is now embedded directly
 * in the JWT tokens themselves, making the system fully stateless.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false, unique = true, length = 80)
    private String username;

    @Column(nullable = false, length = 80)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "users_roles",
            joinColumns = @JoinColumn(name = "USER_ID"),
            inverseJoinColumns = @JoinColumn(name = "ROLE_ID"),
            // Ensure that a user can have a role only once, the user_id and role_id combination must be unique
            uniqueConstraints = @UniqueConstraint(columnNames = {"USER_ID", "ROLE_ID"})
    )
    private List<Role> roles;

    // RefreshToken relationship removed - no longer needed
    // All refresh token data is now embedded in JWT tokens as claims
}