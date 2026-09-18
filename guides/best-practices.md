# Spring Security 6.x Best Practices

A concise, opinionated reference for the idiomatic 6.x style used throughout this repo, with the
deprecated patterns it replaces. All snippets are the lambda DSL — the only style that survives into
Spring Security 7.

← Back to the [README](../README.md)

---

## The one structural rule

No `WebSecurityConfigurerAdapter` (removed in 6.0). Every configuration is a plain `@Configuration`
exposing a `SecurityFilterChain` bean built with the lambda DSL.

| ❌ Old (deprecated / removed) | ✅ Current (6.x) |
|---|---|
| `extends WebSecurityConfigurerAdapter` | `@Bean SecurityFilterChain` |
| `.and()` chaining | Lambda DSL (removed in 7.0) |
| `authorizeRequests()` / `antMatchers()` / `mvcMatchers()` | `authorizeHttpRequests()` / `requestMatchers()` |
| `@EnableGlobalMethodSecurity(prePostEnabled = true)` | `@EnableMethodSecurity` (pre/post on by default) |
| `configure(AuthenticationManagerBuilder)` | `UserDetailsService` / `AuthenticationManager` beans |
| `NoOpPasswordEncoder`, `withDefaultPasswordEncoder()` | `PasswordEncoderFactories.createDelegatingPasswordEncoder()` |
| `web.ignoring()` for static assets | `permitAll()` (no session cost in 6; keeps headers) |
| `http.headers().frameOptions().disable()` | `frameOptions(f -> f.sameOrigin())` |

---

## Password encoding

```java
@Bean
PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}
```

Stores `{bcrypt}$2a$10$...`. A prefix-less (plaintext) value throws at verification time — never store one.

## Authentication

- Publish a `UserDetailsService` bean (JPA-backed here) — Boot wires it into a `DaoAuthenticationProvider`
  automatically.
- Expose the `AuthenticationManager` from `AuthenticationConfiguration` for a custom login endpoint.
- Prefer the **OAuth2 Resource Server** for JWT over a hand-rolled filter:
  ```java
  http.oauth2ResourceServer(o -> o.jwt(jwt -> jwt.jwtAuthenticationConverter(converter)));
  ```
  It verifies signature, algorithm, and expiry for you.

## Authorization

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/public/**").permitAll()
    .requestMatchers("/admin/**").hasRole("ADMIN")   // ROLE_ prefix added automatically
    .anyRequest().authenticated());
```

- `hasRole("ADMIN")` ≡ `hasAuthority("ROLE_ADMIN")`. Never pass the `ROLE_` prefix to `hasRole`/`roles()`.
- Use `@EnableMethodSecurity` + `@PreAuthorize`/`@PostAuthorize` for object-level rules.

## CSRF

On by default; keep it for cookie/session apps. Disable **only** for stateless bearer-token APIs:

```java
http.csrf(csrf -> csrf.disable()); // correct ONLY when auth is in the Authorization header
```

## CORS

```java
http.cors(Customizer.withDefaults()); // picks up the CorsConfigurationSource bean
```

`setAllowCredentials(true)` cannot be combined with `*` origins — list explicit origins.

## Session management

```java
// stateless API
http.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
// stateful web
http.sessionManagement(s -> s.sessionFixation(f -> f.changeSessionId()).maximumSessions(1));
```

## Security headers

Defaults: `nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, HSTS over HTTPS. CSP is **not**
default — add it:

```java
http.headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'")));
```

## Testing

```java
@SpringBootTest @AutoConfigureMockMvc   // Boot applies springSecurity() to MockMvc
class T {
    @Autowired MockMvc mvc;

    @Test @WithMockUser(roles = "ADMIN")
    void adminOk() throws Exception { mvc.perform(get("/admin")).andExpect(status().isOk()); }

    @Test void csrf() throws Exception {
        mvc.perform(post("/x").with(user("u")).with(csrf())).andExpect(status().isOk());
        mvc.perform(post("/x").with(user("u")).with(csrf().useInvalidToken())).andExpect(status().isForbidden());
    }

    @Test void jwt() throws Exception {
        mvc.perform(get("/api").with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_read"))))
           .andExpect(status().isOk());
    }
}
```

Key toolkit: `@WithMockUser`, and the `httpBasic()`, `csrf()`, `user()`, `jwt()` request post-processors;
`formLogin()` builder; `authenticated()`/`unauthenticated()` result matchers; `MockHttpSession`.

---

← Back to the [README](../README.md) · see also [attacks.md](attacks.md)
