package com.epam.microservices.auth.service.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Component
public class CorsCustomizer {

  public void corsCustomizer(HttpSecurity http) throws Exception {
    http.cors(c -> {
      CorsConfigurationSource source = s -> {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        configuration.setAllowedOrigins(List.of(
          "http://127.0.0.1:3000",
          "http://localhost:8099"
        ));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowedMethods(List.of("*"));
        return configuration;
      };
      c.configurationSource(source);
    });
  }
}