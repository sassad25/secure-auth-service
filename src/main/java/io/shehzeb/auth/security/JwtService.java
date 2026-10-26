package io.shehzeb.auth.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.shehzeb.auth.domain.Role;
import io.shehzeb.auth.domain.UserAccount;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Issues signed HS256 JWT access tokens. The token carries the subject (user id), username, and
 * roles as a {@code roles} claim consumed by the resource-server authority mapper.
 */
@Service
public class JwtService {

    private final JwtProperties properties;
    private final SecretKey key;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
        this.key = Keys.hmacShaKeyFor(properties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public String createAccessToken(UserAccount user) {
        Instant now = Instant.now();
        Instant expiry = now.plus(properties.getAccessTokenTtl());
        List<String> roles = user.getRoles().stream().map(Role::name).toList();

        return Jwts.builder()
                .issuer(properties.getIssuer())
                .subject(user.getId().toString())
                .claim("username", user.getUsername())
                .claim("roles", roles)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public SecretKey signingKey() {
        return key;
    }
}
