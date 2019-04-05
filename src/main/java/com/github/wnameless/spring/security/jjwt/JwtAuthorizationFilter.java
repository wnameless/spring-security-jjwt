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

import static com.github.wnameless.spring.security.jjwt.JwtTokenConstants.TOKEN_HEADER;
import static com.github.wnameless.spring.security.jjwt.JwtTokenConstants.TOKEN_PREFIX;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;

/**
 * 
 * {@link JwtAuthorizationFilter} filters the JWT header in the request. If the
 * token in the JWT header is valid, the request is authenticated automatically.
 *
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

  private static final Logger log =
      LoggerFactory.getLogger(JwtAuthorizationFilter.class);

  private final String jwtSecret;

  public JwtAuthorizationFilter(AuthenticationManager authenticationManager,
      String jwtSecret) {
    super(authenticationManager);
    this.jwtSecret = jwtSecret;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request,
      HttpServletResponse response, FilterChain filterChain)
      throws IOException, ServletException {
    Authentication authentication = getAuthentication(request);
    String header = request.getHeader(TOKEN_HEADER);

    if (StringUtils.isEmpty(header) || !header.startsWith(TOKEN_PREFIX)) {
      filterChain.doFilter(request, response);
      return;
    }

    SecurityContextHolder.getContext().setAuthentication(authentication);
    filterChain.doFilter(request, response);
  }

  private UsernamePasswordAuthenticationToken getAuthentication(
      HttpServletRequest request) {
    String token = request.getHeader(TOKEN_HEADER);
    if (!StringUtils.isEmpty(token)) {
      try {
        byte[] signingKey = jwtSecret.getBytes();

        Jws<Claims> parsedToken = Jwts.parser().setSigningKey(signingKey)
            .parseClaimsJws(token.replace(TOKEN_PREFIX, ""));

        String username = parsedToken.getBody().getSubject();

        List<GrantedAuthority> authorities =
            ((List<?>) parsedToken.getBody().get("rol")).stream()
                .map(
                    authority -> new SimpleGrantedAuthority((String) authority))
                .collect(Collectors.toList());

        if (!StringUtils.isEmpty(username)) {
          return new UsernamePasswordAuthenticationToken(username, null,
              authorities);
        }
      } catch (ExpiredJwtException exception) {
        log.warn("Parse expired JWT : {} failed : {}", token,
            exception.getMessage());
      } catch (UnsupportedJwtException exception) {
        log.warn("Parse unsupported JWT : {} failed : {}", token,
            exception.getMessage());
      } catch (MalformedJwtException exception) {
        log.warn("Parse malformed JWT : {} failed : {}", token,
            exception.getMessage());
      } catch (SignatureException exception) {
        log.warn("Parse JWT with invalid signature : {} failed : {}", token,
            exception.getMessage());
      } catch (IllegalArgumentException exception) {
        log.warn("Parse null or empty or only whitespace JWT : {} failed : {}",
            token, exception.getMessage());
      }
    }

    return null;
  }

}