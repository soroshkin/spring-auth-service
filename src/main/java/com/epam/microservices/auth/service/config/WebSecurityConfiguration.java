package com.epam.microservices.auth.service.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;

@EnableWebSecurity
public class WebSecurityConfiguration {

  @Value("${gateway.server.base-url}")
  private String gatewayBaseUrl;

  private final CorsCustomizer corsCustomizer;

  public WebSecurityConfiguration(CorsCustomizer corsCustomizer) {
    this.corsCustomizer = corsCustomizer;
  }

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    corsCustomizer.corsCustomizer(http);
    return http
      .authorizeRequests()
      .antMatchers("/favicon.ico", "/resources/**", "/error", "/exchange/**", "/demo/**")
      .permitAll()
      .and()
      .authorizeRequests()
      .anyRequest()
      .authenticated()
      .and()
      .formLogin()
      .loginProcessingUrl("/login")
      .successHandler(new RewriteHostSavedRequestAwareSuccessHandler())
      .and()
      .build();
  }

  private class RewriteHostSavedRequestAwareSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
      SavedRequest savedRequest = this.requestCache.getRequest(request, response);
      logger.info(savedRequest);
      if (savedRequest == null) {
        super.onAuthenticationSuccess(request, response, authentication);
        return;
      }
      String targetUrlParameter = getTargetUrlParameter();
      if (isAlwaysUseDefaultTargetUrl()
        || (targetUrlParameter != null && StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
        this.requestCache.removeRequest(request, response);
        super.onAuthenticationSuccess(request, response, authentication);
        return;
      }
      clearAuthenticationAttributes(request);
      // Use the DefaultSavedRequest URL
      URL url = new URL(savedRequest.getRedirectUrl());
      String targetUrl = gatewayBaseUrl + url.getFile();

      logger.info(targetUrl);
      getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    @Override
    public void setRequestCache(RequestCache requestCache) {
      this.requestCache = requestCache;
    }
  }
}
