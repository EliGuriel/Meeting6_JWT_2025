package com.example.stage4.service;

import com.example.stage4.entity.Role;
import com.example.stage4.entity.User;
import com.example.stage4.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * CustomUserDetailsService - Stage 4 Enhanced Implementation
 * 
 * This service loads user details from the database for authentication purposes.
 * It has been enhanced with proper exception handling and security validations.
 * 
 * Key improvements:
 * - Proper exception throwing instead of returning null
 * - Account status validations (enabled, non-locked)
 * - Role mapping with Spring Security authorities
 * - Comprehensive logging for security monitoring
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Load user details by username for authentication
     * 
     * @param username The username to search for
     * @return UserDetails object containing user information and authorities
     * @throws UsernameNotFoundException if user is not found
     * @throws DisabledException if user account is disabled
     * @throws LockedException if user account is locked
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("Loading user details for username: " + username);
        
        User user = userRepository.findByUsername(username);

        if (user != null) {
            System.out.println("User found: " + username + " with " + user.getRoles().size() + " roles");
            
            UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                    user.getUsername(),
                    user.getPassword(),
                    mapRolesToAuthorities(user.getRoles())
            );
            
            // Validate account status
            if (!userDetails.isEnabled()) {
                System.out.println("User account is disabled: " + username);
                throw new DisabledException("User account is disabled: " + username);
            }

            if (!userDetails.isAccountNonLocked()) {
                System.out.println("User account is locked: " + username);
                throw new LockedException("User account is locked: " + username);
            }

            System.out.println("User details loaded successfully for: " + username);
            return userDetails;

        } else {
            // FIXED: Always throw UsernameNotFoundException instead of returning null
            // This is the proper Spring Security way and ensures consistent error handling
            System.out.println("User not found: " + username);
            throw new UsernameNotFoundException("User not found: " + username);
        }
    }

    /**
     * Map user roles to Spring Security GrantedAuthority objects
     * 
     * @param roles List of user roles from the database
     * @return Collection of GrantedAuthority objects
     */
    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(List<Role> roles) {
        return roles.stream()
                // Add the prefix "ROLE_" to the role name, it is required by Spring Security
                .map(role -> {
                    String authority = "ROLE_" + role.getRoleName();
                    System.out.println("Mapping role to authority: " + authority);
                    return new SimpleGrantedAuthority(authority);
                })
                .collect(Collectors.toList());
    }
}