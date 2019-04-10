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

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * 
 * {@link AbstractJwtSecurityConfiguration} extends from
 * {@link WebSecurityConfigurerAdapter} which also means all Spring security
 * configurations are allowed.<br>
 * <br>
 * {@link AbstractJwtSecurityConfiguration} pre-configures all necessary
 * settings including:<br>
 * 1. {@link CorsConfiguration#applyPermitDefaultValues() CORS}<br>
 * 2. CSRF disabled<br>
 * 3. {@link JwtAuthenticationFilter}<br>
 * 4. {@link JwtAuthorizationFilter}<br>
 * 5. Stateless session<br>
 * <br>
 * Quick Start:
 * 
 * <pre>
 * &#64;EnableWebSecurity
 * public class JwtSecurityConfiguration
 *     extends AbstractJwtSecurityConfiguration {
 * 
 *   &#64;Override
 *   protected void configure(HttpSecurity http) throws Exception {
 *     super.configure(http); // Important!!!
 * 
 *     http.antMatcher("/api/**") //
 *         .authorizeRequests().anyRequest().authenticated();
 *   }
 * 
 *   &#64;Override
 *   public void configure(AuthenticationManagerBuilder auth) throws Exception {
 *     auth.inMemoryAuthentication().withUser("user")
 *         .password(passwordEncoder().encode("password"))
 *         .authorities("ROLE_USER");
 *   }
 * 
 *   &#64;Bean
 *   public PasswordEncoder passwordEncoder() {
 *     return new BCryptPasswordEncoder();
 *   }
 * }
 * </pre>
 */
@ComponentScan
@Configuration
public abstract class AbstractJwtSecurityConfiguration
    extends WebSecurityConfigurerAdapter {

  @Autowired
  private InternalJwtSecurityProperties jwtSecurityProps;

  @Autowired(required = false)
  private JwtExpirationExtendingService jwtExpirationExtendingService;

  @Autowired(required = false)
  private JwtExpirationExtendingPolicy jwtExpirationExtendingPolicy;

  @PostConstruct
  private void init() {
    if (jwtExpirationExtendingPolicy != null
        && jwtExpirationExtendingService == null) {
      jwtExpirationExtendingService =
          new MapDBJwtExpirationExtendingService();
    }
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.cors().configurationSource(corsConfigurationSource()).and() //
        .csrf().disable().addFilter(new JwtAuthenticationFilter( //
            authenticationManager(), //
            jwtSecurityProps.getJwtAuthUrl(), //
            jwtSecurityProps.getJwtSecret(), //
            jwtSecurityProps.getJwtExpiration()))
        .addFilter(jwtExpirationExtendingPolicy == null
            ? new JwtAuthorizationFilter( //
                authenticationManager(), //
                jwtSecurityProps.getJwtSecret())
            : new JwtExpirationExtendingFilter( //
                authenticationManager(), //
                jwtSecurityProps.getJwtSecret(), //
                jwtExpirationExtendingService, //
                jwtExpirationExtendingPolicy))
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
  }

  protected CorsConfigurationSource corsConfigurationSource() {
    final UrlBasedCorsConfigurationSource configurationSource =
        new UrlBasedCorsConfigurationSource();
    CorsConfiguration config =
        new CorsConfiguration().applyPermitDefaultValues();
    configurationSource.registerCorsConfiguration("/**", config);

    return configurationSource;
  }

}
