# Using OATH and JWT in SpringBoot

## Why doing this
I am building an application where I want to have authentication. I used JWT tokens before to authenticate users and manage roles for specific endpoints.
This time I wanted to try something different and was already interested in using OAuth 2.0 login with Google. OAuth is an authorization framework that issues access (and ID) tokens rather than traditional server-side sessions. Some libraries still create an HTTP session to store the OAuth state, but the protocol itself is token based. I still want to define my own roles and keep tighter control over the claims the client receives.
So I am combining the two approaches. Google handles the OAuth dance, then I read the ID token in my Spring Boot backend, enrich it with my own role model, and mint the JWT that the rest of the API consumes.

> Note: OATH (Open Authentication) is the standards body behind HOTP/TOTP one-time passwords. My project is using OAuth 2.0, the authorization framework, not OATH.

## Create user and user roles persistently
After Google sends me back to the backend, the `JwtTokenService` extracts the OpenID Connect claims and uses the email address as the unique key. I call `UserService.registerNewUser` only when that email is not in the database yet, so I do not overwrite existing data. The service attaches a default `DEFAULT_USER` authority to every new account and swaps it for `ADMIN` when the email matches the `app.admin.email` value from the environment. This way I keep the flexibility to promote myself (or someone else) without hard-coding identities, and every login gets a `User` row together with the granted authorities persisted through JPA.

```java
public User registerNewUser(User entity) {
  Authority.AuthorityBuilder authorityBuilder = Authority.builder();
  if (entity.getEmail() != null) {
    authorityBuilder.username(entity.getEmail());
  }

  Set<Authority> authorities = new HashSet<>();
  if (entity.getEmail() != null && entity.getEmail().equalsIgnoreCase(adminEmail)) {
    authorities.add(authorityBuilder.authority("ADMIN").build());
  } else {
    authorities.add(authorityBuilder.authority("DEFAULT_USER").build());
  }

  entity = entity.toBuilder().authorities(authorities).build();
  return userRepository.save(entity);
}
```

## Secured endpoints
All admin functionality now sits behind Spring Security. In `SecurityConfig` I keep the session stateless and wire both OAuth login and the resource server flow. Every `/api/dashboard/**`, `/api/catalog/**`, `/api/media/**`, and `/api/config/**` route requires the `ADMIN` authority, while public GET routes remain open for a read-only portfolio site. Successful logins either return a JSON payload with the signed JWT or, for the small test UI, render a popup page that stores the token in `localStorage`. Once the frontend sends the JWT back in the `Authorization` header, the resource server validates it before the controller logic runs.

```java
.authorizeHttpRequests(auth -> auth
    .requestMatchers(HttpMethod.GET, "/login").permitAll()
    .requestMatchers("/api/dashboard/**").hasAuthority("ADMIN")
    .requestMatchers("/api/catalog/**").hasAuthority("ADMIN")
    .requestMatchers("/api/media/**").hasAuthority("ADMIN")
    .requestMatchers("/api/config/**").hasAuthority("ADMIN")
    .anyRequest().permitAll())
```

## How it works
At a high level Google handles the user identity, my backend enriches that identity with roles, and the client uses the returned JWT to call the protected API. The pieces below describe the moving parts I wired together.

### application.properties
Configuration lives in `application.properties` with everything sensitive pulled from `.env`. PostgreSQL connection values, Google OAuth client credentials, and the Base64 encoded `JWT_SECRET_BASE64` are all injected through Spring. I also set `jwt.expiration-seconds=3600` for one-hour access tokens and `app.admin.email` so I can decide who gets admin rights without rebuilding.

```properties
spring.datasource.url=jdbc:postgresql://${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
spring.security.oauth2.client.registration.google.client-id=${OAUTH_CLIENT_ID}
spring.security.oauth2.client.registration.google.client-secret=${OAUTH_CLIENT_SECRET}
jwt.secret=${JWT_SECRET_BASE64}
jwt.expiration-seconds=3600
app.admin.email=${ADMIN_USER}
```

### SecurityFilterChain
The filter chain disables CSRF (because this is an API), enforces `SessionCreationPolicy.STATELESS`, and registers both OAuth login and the JWT resource server. Route rules block `/api/v1/admin/**`, `/api/v1/projects/**`, `/api/v1/status/**`, and `/api/v1/images/**` unless the caller has the `ADMIN` authority, while `/login` remains public for the OAuth redirect. `@EnableMethodSecurity` is on, so I can still add method-level annotations later.

```java
http
    .csrf(csrf -> csrf.disable())
    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .oauth2Login(oauth2 -> oauth2
        .loginPage("/login")
        .successHandler(successHandler))
    .oauth2ResourceServer(oauth2 -> oauth2
        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));
```

### Login redirect endpoint
Spring Security expects the OAuth2 client flow to start at `/oauth2/authorization/{registrationId}`. I added a small, dedicated controller so navigating to the easy-to-remember `/login` path just hands off to `redirect:/oauth2/authorization/google`, letting the framework take over the authorization code flow.

```java
@GetMapping("/login")
public String login() {
  return "redirect:/oauth2/authorization/google";
}
```

### SuccesHandler
I overrode the OAuth success handler so I can mint my own JWT immediately after Google signs in the user. When the request comes from the lightweight test UI, the handler writes a tiny HTML page that drops the token into `localStorage` and closes the popup. For API clients, the handler returns `{ "accessToken": "..." }`, making it simple to store in memory or cookies.

```java
AuthenticationSuccessHandler successHandler = (request, response, authentication) -> {
  String token = jwtTokenService.generateToken(authentication);
  HttpSession session = request.getSession(false);
  response.setContentType(MediaType.APPLICATION_JSON_VALUE);
  objectMapper.writeValue(response.getWriter(), Map.of("accessToken", token));
};
```

### JwtAuthenticationConverter
Because I add a custom `authorities` claim, I also provide a `JwtAuthenticationConverter`. It accepts either a comma-separated string or an array, turning each value into a `SimpleGrantedAuthority`. That keeps the `SecurityContext` aligned with whatever I store in the token and avoids hard-coded role mapping.

```java
converter.setJwtGrantedAuthoritiesConverter(jwt -> {
  Object roles = jwt.getClaim("authorities");
  if (roles instanceof String rolesStr) {
    return List.of(rolesStr.split(","))
        .stream()
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toList());
  } else if (roles instanceof Collection<?> rolesList) {
    return rolesList.stream()
        .map(Object::toString)
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toList());
  }
  return List.of();
});
```

### JwtDecoder
The resource server uses `NimbusJwtDecoder` with the same HMAC-SHA256 secret that the token service uses for signing. The key is derived from the Base64 value in `jwt.secret`, so every environment just needs an updated secret in the `.env` file.

```java
@Bean
public JwtDecoder jwtDecoder() {
  byte[] keyBytes = io.jsonwebtoken.io.Decoders.BASE64.decode(this.SECRETKEY);
  SecretKey spec = new SecretKeySpec(keyBytes, "HmacSHA256");
  return NimbusJwtDecoder.withSecretKey(spec).build();
}
```

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
- [Spring Authorization Servee Samples](https://github.com/spring-projects/spring-authorization-server/tree/main/samples)
