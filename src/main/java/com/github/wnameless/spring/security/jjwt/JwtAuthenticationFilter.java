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

import static com.github.wnameless.spring.security.jjwt.JwtTokenConstants.TOKEN_AUDIENCE;
import static com.github.wnameless.spring.security.jjwt.JwtTokenConstants.TOKEN_ISSUER;
import static com.github.wnameless.spring.security.jjwt.JwtTokenConstants.TOKEN_TYPE;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

/**
 * 
 * {@link JwtAuthenticationFilter} filters provided url and authenticates the
 * both url parameters <b>username</b> &amp; <b>password</b> with given
 * {@link AuthenticationManager}. If the authentication is success, it returns a
 * JWT string in response body.
 *
 */
public class JwtAuthenticationFilter
    extends UsernamePasswordAuthenticationFilter {

  private static final Logger log =
      LoggerFactory.getLogger(JwtAuthenticationFilter.class);

  private final AuthenticationManager authenticationManager;
  private final byte[] signingKey;
  private final long jwtExpiration;

  public JwtAuthenticationFilter(AuthenticationManager authenticationManager,
      String jwtAuthUrl, String jwtSecret, long jwtExpiration) {
    this.authenticationManager = authenticationManager;
    signingKey = jwtSecret.getBytes();
    this.jwtExpiration = jwtExpiration;

    setFilterProcessesUrl(jwtAuthUrl);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) {
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    Authentication authenticationToken =
        new UsernamePasswordAuthenticationToken(username, password);

    return authenticationManager.authenticate(authenticationToken);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request,
      HttpServletResponse response, FilterChain filterChain,
      Authentication authentication) {
    User user = ((User) authentication.getPrincipal());

    List<String> roles = user.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority).collect(Collectors.toList());

    String token = Jwts.builder()
        .signWith(Keys.hmacShaKeyFor(signingKey), SignatureAlgorithm.HS512)
        .setHeaderParam("typ", TOKEN_TYPE).setIssuer(TOKEN_ISSUER)
        .setAudience(TOKEN_AUDIENCE).setSubject(user.getUsername())
        .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
        .claim("rol", roles).compact();

    try {
      response.getWriter().write(token);
    } catch (IOException e) {
      log.error("Write the JWT failed : {}", e.getMessage());
    }
  }

}