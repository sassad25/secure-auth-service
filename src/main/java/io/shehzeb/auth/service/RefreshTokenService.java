package io.shehzeb.auth.service;

import io.shehzeb.auth.domain.RefreshToken;
import io.shehzeb.auth.domain.RefreshTokenRepository;
import io.shehzeb.auth.security.JwtProperties;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Manages opaque refresh tokens with rotation and revocation.
 *
 * <p>Clients receive a random token value; only its SHA-256 hash is persisted, so a database leak
 * does not expose usable tokens. On refresh the presented token is validated and immediately
 * rotated (old one revoked, new one issued), mitigating replay.</p>
 */
@Service
public class RefreshTokenService {

    private final RefreshTokenRepository repository;
    private final JwtProperties properties;
    private final java.security.SecureRandom random = new java.security.SecureRandom();

    public RefreshTokenService(RefreshTokenRepository repository, JwtProperties properties) {
        this.repository = repository;
        this.properties = properties;
    }

    /** Issues a new refresh token for a user and returns its raw value (shown once to the client). */
    @Transactional
    public String issue(UUID userId) {
        String rawValue = generateRawValue();
        RefreshToken token = new RefreshToken(
                UUID.randomUUID(), userId, hash(rawValue),
                Instant.now().plus(properties.getRefreshTokenTtl()));
        repository.save(token);
        return rawValue;
    }

    /** Validates and rotates a refresh token, returning the owning user id. */
    @Transactional
    public UUID rotate(String presentedValue) {
        RefreshToken token = repository.findByTokenHash(hash(presentedValue))
                .orElseThrow(() -> new InvalidTokenException("Unknown refresh token"));
        if (!token.isActive()) {
            throw new InvalidTokenException("Refresh token expired or revoked");
        }
        token.revoke();
        repository.save(token);
        return token.getUserId();
    }

    @Transactional
    public void revokeAll(UUID userId) {
        repository.revokeAllForUser(userId);
    }

    private String generateRawValue() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] out = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(out);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
