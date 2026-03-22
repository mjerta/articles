+++
title = 'AUTH+JWT in SpringBoot'
date = 2026-03-22T13:08:27+01:00
author = "Maarten Postma"
authorAvatar = "images/avatar.png"
+++

### JwtTokenService
`JwtTokenService` takes the authenticated `OidcUser`, copies the relevant Google claims, persists the user when necessary, and finally builds the JWT with issuer timestamps, profile details, and the calculated authorities. Tokens expire after an hour, which is enough for the admin dashboard session without keeping stale privileges around forever.

```java
public String generateToken(Authentication authentication) {
  Instant now = Instant.now();
  this.googleClaims = this.extractClaims(authentication);
  if (this.userService.checkIfUserExist(googleClaims.get("email"))) {
    this.userService.registerNewUser(User.builder()
        .externalId(this.googleClaims.get("external_id"))
        .email(this.googleClaims.get("email"))
        .firstName(this.googleClaims.get("first_name"))
        .lastName(this.googleClaims.get("last_name"))
        .profilePhoto(this.googleClaims.get("profile_photo"))
        .lastLoginAt(now)
        .build());
  }
  Set<String> authorities = userService.checkForRoles(this.googleClaims.get("email"));

  return Jwts.builder()
      .setSubject(authentication.getName())
      .setIssuedAt(Date.from(now))
      .setExpiration(Date.from(now.plusSeconds(expirationSeconds)))
      .claim("authorities", authorities)
      .signWith(signingKey, SignatureAlgorithm.HS256)
      .compact();
}
```

### UserService
`UserService` wraps the repository calls so I can keep role logic in one place. It registers new users with either `ADMIN` or `DEFAULT_USER`, exposes a `checkIfUserExist` helper to avoid duplicate rows, and returns the stored authorities as simple strings when the token service needs them. That makes it trivial to plug more roles in later while keeping the authentication flow readable.

```java
public Set<String> checkForRoles(String email) {
  return userRepository.findByEmail(email)
      .map(User::getAuthorities)
      .filter(authorities -> !authorities.isEmpty())
      .map(authorities -> authorities.stream()
          .map(Authority::getAuthority)
          .collect(Collectors.toSet()))
      .orElseGet(() -> Collections.singleton("DEFAULT_USER"));
}
```

## Sources to use
- [Spring Security Reference: OAuth2 Client](https://docs.spring.io/spring-security/reference/servlet/oauth2/client/index.html)
- [Spring Security Reference: Resource Server JWT](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html)
- [Spring Boot Reference: Externalized Configuration](https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#features.external-config)
- [Spring Authorization Server Samples](https://github.com/spring-projects/spring-authorization-server/tree/main/samples)
