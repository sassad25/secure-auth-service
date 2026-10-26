package io.shehzeb.auth.service;

/** Raised on registration when the username is already taken. Mapped to HTTP 409. */
public class UsernameTakenException extends RuntimeException {
    public UsernameTakenException(String username) {
        super("Username already taken: " + username);
    }
}
