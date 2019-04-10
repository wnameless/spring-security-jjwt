[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.wnameless.spring/spring-security-jjwt/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.wnameless.spring/spring-security-jjwt)

spring-security-jjwt
=============
Integrate the Java JSON Web Token(jjwt) library into Spring Security

## Purpose
Make web API protection by JWT in Spring Security like a breeze

# Maven Repo
```xml
<dependency>
	<groupId>com.github.wnameless.spring</groupId>
	<artifactId>spring-security-jjwt</artifactId>
	<version>0.2.0</version>
</dependency>
```

## Quick Start

Extend AbstractJwtSecurityConfiguration to enable JWT security<br>
AbstractJwtSecurityConfiguration pre-configures all necessary settings including:<br>
1. CORS
2. CSRF disabled
3. JwtAuthenticationFilter
4. JwtAuthorizationFilter
5. Stateless session
```java
@EnableWebSecurity
public class JwtSecurityConfiguration extends AbstractJwtSecurityConfiguration {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    super.configure(http); // IMPORTANT!!!

    http.antMatcher("/api/**") // Using JWT to protect the API endpoint
        .authorizeRequests().anyRequest().authenticated();
  }

  @Override
  public void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication().withUser("user")
        .password(passwordEncoder().encode("password"))
        .authorities("ROLE_USER");
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
```
IMPORTANT: remember to execute super.configure(http) at the first line of #configure(HttpSecurity)

Run test Application & Controller
```java
@SpringBootApplication
public class JwtApplication {

  public static void main(String... args) {
    SpringApplication.run(JwtApplication.class, args);
  }

  @RequestMapping("/api/data")
  @RestController
  public static class DataController {

    @GetMapping
    public String getData() {
      return "Private data";
    }

  }

}
```

Test JWT with Axios
```javascript
var token;

axios.post('http://localhost:8080/api/auth?username=user&password=password')
  .then(res => {
    token = res.data;
  });

axios.get('http://localhost:8080/api/data', { headers: { Authorization: `Bearer ${token}` } })
  .then(res => { console.log(res.data) });
```

## Advanced Configuration

By application.properties
```
# default: /api/auth
jwt.auth-url=/api/login
# 512 bytes at least
jwt.secret=QeThWmZq4t7w!z%C*F-JaNdRgUjXn2r5u8x/A?D(G+KbPeShVmYp3s6v9y$B&E)H
# default: 604800000(7 days)
jwt.expiration=432000000 
```

By @Bean, JwtSecurityProperties bean overides settings in application.properties
```java
@Bean
public JwtSecurityProperties jwtSecurityProperties() {
  return new JwtSecurityProperties(
      "/api/login",
      "QeThWmZq4t7w!z%C*F-JaNdRgUjXn2r5u8x/A?D(G+KbPeShVmYp3s6v9y$B&E)H",
      432000000);
}
```

## Expiration Extending Service

Since v0.2.0, JWT expiration extending service has been added<br>
<br>
The Expiration Extending Service can be enable simply by providing a JwtExpirationExtendingPolicy bean<br>
JwtExpirationExtendingPolicy is called whenever a request JWT is expired<br>
Following example shows how to extend an expired JWT, only if the token was used in past 2 days
```java
@Bean
JwtExpirationExtendingPolicy jwtExpirationExtendingPolicy() {
  return (jwtClaims, lastLoginTime) -> {
    if (lastLoginTime.isPresent()) {
      return new Date().getTime() - lastLoginTime.get()
          .getTime() < TimeUnit.MILLISECONDS.convert(2, TimeUnit.DAYS);
    } else {
      return false;
    }
  };
}
```

By default, the JwtExpirationExtendingService wipes out all last-login records which are outdated for 2 weeks<br>
However you can provide your JwtExpirationExtendingService to meet your need in JwtExpirationExtendingPolicy
```java
@Bean
JwtExpirationExtendingService jwtExpirationExtendingService() {
  return new MapDBJwtExpirationExtendingService(
      TimeUnit.MICROSECONDS.convert(180, TimeUnit.DAYS));
}
```
