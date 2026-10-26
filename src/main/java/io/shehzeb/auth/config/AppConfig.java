package io.shehzeb.auth.config;

import io.shehzeb.auth.security.JwtProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Activates {@link JwtProperties} binding. */
@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class AppConfig {
}
