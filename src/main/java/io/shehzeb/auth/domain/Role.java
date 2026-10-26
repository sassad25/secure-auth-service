package io.shehzeb.auth.domain;

/** Application roles for RBAC. Mapped to Spring Security authorities as {@code ROLE_<name>}. */
public enum Role {
    USER,
    ADMIN
}
