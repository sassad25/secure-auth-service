package io.shehzeb.auth.service;

/** Raised when a refresh token is unknown, expired, or revoked. Mapped to HTTP 401. */
public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(String message) {
        super(message);
    }
}
