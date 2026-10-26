package io.shehzeb.auth.service;

/** Raised on login when credentials do not match. Mapped to HTTP 401. */
public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException() {
        super("Invalid username or password");
    }
}
