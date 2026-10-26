package io.shehzeb.auth.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Externalized JWT settings. In production the secret must be supplied via environment/secret store
 * (never committed). The default here is for local/dev only.
 */
@ConfigurationProperties(prefix = "auth.jwt")
public class JwtProperties {

    /** HMAC signing secret (Base64 or raw). Must be at least 32 bytes for HS256. */
    private String secret = "dev-only-secret-change-me-please-32bytes-minimum!!";

    /** Access token lifetime. */
    private Duration accessTokenTtl = Duration.ofMinutes(15);

    /** Refresh token lifetime. */
    private Duration refreshTokenTtl = Duration.ofDays(7);

    private String issuer = "secure-auth-service";

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public Duration getAccessTokenTtl() {
        return accessTokenTtl;
    }

    public void setAccessTokenTtl(Duration accessTokenTtl) {
        this.accessTokenTtl = accessTokenTtl;
    }

    public Duration getRefreshTokenTtl() {
        return refreshTokenTtl;
    }

    public void setRefreshTokenTtl(Duration refreshTokenTtl) {
        this.refreshTokenTtl = refreshTokenTtl;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
}
