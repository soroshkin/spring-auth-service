package com.epam.microservices.auth.service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class WebSecurityConfiguration {

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http
      .authorizeRequests()
      .antMatchers("/favicon.ico", "/resources/**", "/error")
      .permitAll()
      .and()
      .authorizeRequests()
      .anyRequest().authenticated()
      .and()
      .formLogin(Customizer.withDefaults());

    return http.build();
  }
}
