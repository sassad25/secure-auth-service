package io.shehzeb.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Secure Auth Service.
 *
 * <p>Provides user registration and login, issues signed JWT access tokens and rotating refresh
 * tokens, and enforces role-based access control (RBAC). Protected resources are guarded by the
 * same JWTs via an OAuth2 resource-server filter.</p>
 */
@SpringBootApplication
public class SecureAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureAuthServiceApplication.class, args);
    }
}
