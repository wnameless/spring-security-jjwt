/*
 *
 * Copyright 2019 Wei-Ming Wu
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */
package com.github.wnameless.spring.security.jjwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
final class InternalJwtSecurityProperties implements SecurityProperties {

  private static final Logger log =
      LoggerFactory.getLogger(InternalJwtSecurityProperties.class);

  private static final String defaultAuthUrl = "/api/auth";
  private static final String defaultJwtSecret =
      "9z$C&F)H@McQfTjWnZr4u7x!A%D*G-KaNdRgUkXp2s5v8y/B?E(H+MbQeShVmYq3";
  private static final long defaultJwtExpiration = 604800000;

  private final String jwtAuthUrl;
  private final String jwtSecret;
  private final long jwtExpiration;

  InternalJwtSecurityProperties(
      @Value("${jwt.auth-url:" + defaultAuthUrl + "}") String jwtAuthUrl,
      @Value("${jwt.secret:" + defaultJwtSecret + "}") String jwtSecret,
      @Value("${jwt.expiration:" + defaultJwtExpiration
          + "}") long jwtExpiration,
      @Autowired(
          required = false) JwtSecurityProperties jwtSecurityProperties) {
    if (jwtSecurityProperties != null) {
      this.jwtAuthUrl = jwtSecurityProperties.getJwtAuthUrl();
      this.jwtSecret = jwtSecurityProperties.getJwtSecret();
      this.jwtExpiration = jwtSecurityProperties.getJwtExpiration();
    } else {
      this.jwtAuthUrl = jwtAuthUrl;
      this.jwtSecret = jwtSecret;
      this.jwtExpiration = jwtExpiration;
    }

    if (jwtAuthUrl.equals(defaultAuthUrl)) {
      log.info("JWT auth URL is set to default: {}", defaultAuthUrl);
    } else {
      log.info("JWT auth URL is set to: {}", jwtAuthUrl);
    }
    if (jwtSecret.equals(defaultJwtSecret)) {
      log.warn(
          "No JWT secret set, falling back to default JWT secret(signing key)");
    }
    if (jwtExpiration == defaultJwtExpiration) {
      log.info("JWT expiration is set to default : {} milliseconds",
          defaultJwtExpiration);
    } else {
      log.info("JWT expiration is set to : {} milliseconds", jwtExpiration);
    }
  }

  @Override
  public String getJwtAuthUrl() {
    return jwtAuthUrl;
  }

  @Override
  public String getJwtSecret() {
    return jwtSecret;
  }

  @Override
  public long getJwtExpiration() {
    return jwtExpiration;
  }

}
