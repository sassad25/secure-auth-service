package io.shehzeb.auth.api;

import io.shehzeb.auth.service.InvalidCredentialsException;
import io.shehzeb.auth.service.InvalidTokenException;
import io.shehzeb.auth.service.UsernameTakenException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/** RFC 7807 error translation for the auth API. */
@RestControllerAdvice
public class AuthExceptionHandler {

    @ExceptionHandler(UsernameTakenException.class)
    public ProblemDetail handleTaken(UsernameTakenException ex) {
        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        p.setTitle("Username taken");
        return p;
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ProblemDetail handleBadCreds(InvalidCredentialsException ex) {
        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
        p.setTitle("Authentication failed");
        return p;
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ProblemDetail handleBadToken(InvalidTokenException ex) {
        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
        p.setTitle("Invalid token");
        return p;
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException ex) {
        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Request validation failed");
        p.setTitle("Validation error");
        Map<String, String> errors = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(fe -> errors.put(fe.getField(), fe.getDefaultMessage()));
        p.setProperty("errors", errors);
        return p;
    }
}
