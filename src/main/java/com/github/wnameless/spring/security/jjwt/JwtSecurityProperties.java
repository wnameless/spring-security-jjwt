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

import java.util.Objects;

/**
 * 
 * {@link JwtSecurityProperties} allows user to set up the JWT security service
 * programmatically.<br>
 * <br>
 * For example:<br>
 * 
 * <pre>
 * &#64;Bean
 * public JwtSecurityProperties jwtSecurityProperties() {
 *   return new JwtSecurityProperties(...);
 * }
 * </pre>
 *
 */
public final class JwtSecurityProperties implements SecurityProperties {

  private final String jwtAuthUrl;
  private final String jwtSecret;
  private final long jwtExpiration;

  public JwtSecurityProperties(String jwtAuthUrl, String jwtSecret,
      long jwtExpiration) {
    this.jwtAuthUrl = Objects.requireNonNull(jwtAuthUrl);
    this.jwtSecret = Objects.requireNonNull(jwtSecret);
    this.jwtExpiration = jwtExpiration;
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
