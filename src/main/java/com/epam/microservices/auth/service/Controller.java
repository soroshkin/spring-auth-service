package com.epam.microservices.auth.service;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {

  private Logger logger = LoggerFactory.getLogger(getClass());

  @PostMapping(path = "/exchange/token")
  public Request getToken(@RequestBody Request request) {
    logger.info(request.toString());
    request.setSecret("secret");

    return request;
  }

  @GetMapping(path = "/demo", produces =  "application/json")
  public Request getToken() {
//    logger.info(request.toString());
//    request.setSecret("secret");
    return new Request("sdfsd", "sfdf", "sdfsdf", "sdfsdfsd","sdfsdf");
  }


  private static class Request {

    private String code;

    private String clientId;

    private String grantType;

    private String redirectUri;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String secret;

    @JsonCreator
    public Request(String code,
                    @JsonProperty("client_id") String clientId,
                    @JsonProperty("grant_type") String grantType,
                    @JsonProperty("redirect_uri") String redirectUri,
                    String secret) {
      this.code = code;
      this.clientId = clientId;
      this.grantType = grantType;
      this.redirectUri = redirectUri;
      this.secret = secret;
    }

    public String getCode() {
      return code;
    }

    public String getClientId() {
      return clientId;
    }

    public String getGrantType() {
      return grantType;
    }

    public String getRedirectUri() {
      return redirectUri;
    }

    public String getSecret() {
      return secret;
    }

    public void setSecret(String secret) {
      this.secret = secret;
    }

    @Override
    public String toString() {
      return "Request{" +
        "code='" + code + '\'' +
        ", clientId='" + clientId + '\'' +
        ", grantType='" + grantType + '\'' +
        ", redirectUri='" + redirectUri + '\'' +
        ", secret='" + secret + '\'' +
        '}';
    }
  }
}
