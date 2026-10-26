# Secure Auth Service

A standalone authentication & authorization service built with **Java 17**, **Spring Boot 3.3**, and
**Spring Security 6**. Implements user registration, login, **signed JWT access tokens**, **rotating
refresh tokens**, and **role-based access control (RBAC)** — a reusable security layer for a
microservice ecosystem.

> Author: **Muhammad Shehzeb Assad** — Senior Full Stack Java Developer
> Portfolio: https://github.com/sassad25

---

## Security design

| Concern              | Approach |
|----------------------|----------|
| **Password storage** | BCrypt hashing (`BCryptPasswordEncoder`); plaintext is never stored. |
| **Access tokens**    | Stateless, self-contained **HS256 JWTs** (JJWT), carrying subject, username, and `roles`. |
| **Token validation** | Resource-server filter validates JWTs locally via a `NimbusJwtDecoder` built from the same secret — no network round-trip. |
| **RBAC**             | The `roles` claim maps to `ROLE_*` authorities; endpoints are guarded with `@PreAuthorize("hasRole('ADMIN')")`. |
| **Refresh tokens**   | Opaque, random 256-bit values; only the **SHA-256 hash** is persisted. **Rotated** on every use (old one revoked) to mitigate replay; server-side **revocation** supported (logout). |
| **Statelessness**    | No server sessions; CSRF disabled for a pure token API. |
| **Secrets**          | JWT secret is externalized (`AUTH_JWT_SECRET`); the committed default is dev-only. |

## API

| Method | Path                      | Auth       | Description                                   |
|--------|---------------------------|------------|-----------------------------------------------|
| POST   | `/api/v1/auth/register`   | public     | Create account, returns access + refresh      |
| POST   | `/api/v1/auth/login`      | public     | Authenticate, returns access + refresh        |
| POST   | `/api/v1/auth/refresh`    | public     | Rotate refresh token, returns new tokens      |
| POST   | `/api/v1/auth/logout`     | bearer     | Revoke all refresh tokens for the user        |
| GET    | `/api/v1/me`              | bearer     | Current user profile (any role)               |
| GET    | `/api/v1/admin`           | ROLE_ADMIN | Admin-only resource (RBAC demo)               |

### Example

```bash
# Register
curl -X POST http://localhost:9000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
# -> { "accessToken":"...", "refreshToken":"...", "tokenType":"Bearer", "expiresInSeconds":900 }

# Access a protected resource
curl http://localhost:9000/api/v1/me -H "Authorization: Bearer <accessToken>"

# Refresh (rotates the refresh token)
curl -X POST http://localhost:9000/api/v1/auth/refresh \
  -H "Content-Type: application/json" -d '{"refreshToken":"<refreshToken>"}'
```

## Tech stack

Java 17 · Spring Boot 3.3 · Spring Security 6 (resource server) · JJWT 0.12 · Spring Data JPA ·
PostgreSQL · Flyway · BCrypt · Testcontainers · JUnit 5 · Docker · GitHub Actions.

## Running the tests

```bash
mvn clean verify
```

Integration tests run against real PostgreSQL (Testcontainers) and cover registration, protected
access, refresh-token rotation (old token rejected), duplicate-registration conflict, RBAC
enforcement, and invalid-credential handling.

## Running locally

```bash
docker compose up --build
# service on http://localhost:9000
```

## Project layout

```
src/main/java/io/shehzeb/auth/
├── domain/     # UserAccount, Role, RefreshToken + repositories
├── security/   # JwtService (sign), JwtProperties, SecurityConfig (decode + RBAC)
├── service/    # AuthService, RefreshTokenService, domain exceptions
├── api/        # Auth + profile controllers, DTOs, RFC 7807 error handling
└── config/     # Property binding
src/main/resources/db/migration/   # Flyway schema
```

## License

MIT © Muhammad Shehzeb Assad
