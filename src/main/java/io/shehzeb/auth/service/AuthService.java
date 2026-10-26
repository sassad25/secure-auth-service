package io.shehzeb.auth.service;

import io.shehzeb.auth.api.AuthDtos;
import io.shehzeb.auth.domain.Role;
import io.shehzeb.auth.domain.UserAccount;
import io.shehzeb.auth.domain.UserAccountRepository;
import io.shehzeb.auth.security.JwtProperties;
import io.shehzeb.auth.security.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.EnumSet;
import java.util.UUID;

/**
 * Orchestrates authentication use-cases: registration (BCrypt hashing), login (constant-time
 * credential check), token refresh (rotation), and logout (refresh-token revocation).
 */
@Service
public class AuthService {

    private final UserAccountRepository users;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final JwtProperties jwtProperties;

    public AuthService(UserAccountRepository users,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       RefreshTokenService refreshTokenService,
                       JwtProperties jwtProperties) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.jwtProperties = jwtProperties;
    }

    @Transactional
    public AuthDtos.TokenResponse register(String username, String rawPassword) {
        if (users.existsByUsername(username)) {
            throw new UsernameTakenException(username);
        }
        UserAccount user = new UserAccount(username, passwordEncoder.encode(rawPassword), EnumSet.of(Role.USER));
        users.save(user);
        return issueTokens(user);
    }

    @Transactional
    public AuthDtos.TokenResponse login(String username, String rawPassword) {
        UserAccount user = users.findByUsername(username)
                .orElseThrow(InvalidCredentialsException::new);
        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }
        return issueTokens(user);
    }

    @Transactional
    public AuthDtos.TokenResponse refresh(String refreshToken) {
        UUID userId = refreshTokenService.rotate(refreshToken);
        UserAccount user = users.findById(userId)
                .orElseThrow(() -> new InvalidTokenException("User no longer exists"));
        return issueTokens(user);
    }

    @Transactional
    public void logout(UUID userId) {
        refreshTokenService.revokeAll(userId);
    }

    private AuthDtos.TokenResponse issueTokens(UserAccount user) {
        String accessToken = jwtService.createAccessToken(user);
        String refreshToken = refreshTokenService.issue(user.getId());
        return new AuthDtos.TokenResponse(
                accessToken, refreshToken, "Bearer", jwtProperties.getAccessTokenTtl().toSeconds());
    }
}
