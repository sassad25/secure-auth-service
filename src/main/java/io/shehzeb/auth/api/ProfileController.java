package io.shehzeb.auth.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Example protected resources demonstrating RBAC.
 *
 * <ul>
 *   <li>{@code /me} — any authenticated user.</li>
 *   <li>{@code /admin} — restricted to callers holding {@code ROLE_ADMIN}.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1")
public class ProfileController {

    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "userId", jwt.getSubject(),
                "username", jwt.getClaimAsString("username"),
                "roles", jwt.getClaimAsStringList("roles"));
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> adminOnly(@AuthenticationPrincipal Jwt jwt) {
        return Map.of("message", "Welcome, admin " + jwt.getClaimAsString("username"),
                "secret", List.of("dashboards", "user-management"));
    }
}
