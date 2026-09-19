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

## Handling untrusted input

The framework does not cover these — they are ordinary Java, and they are where most of the remaining
bugs live. Each rule is "structure the call so the dangerous interpretation is impossible", never
"filter the bad characters out".

### SQL: parameterize

```java
List<Account> findByOwner(String owner);                      // Spring Data - bind parameter
@Query("select a from Account a where a.owner = :owner")      // JPQL - named parameter
jdbc.query("select * from accounts where owner = ?", rm, owner);
```

Never build the statement text from input. Escaping is not a substitute: quoting rules differ per
database, and `PreparedStatement` removes the question entirely by sending values out of band.

### Request bodies: bind to a DTO, not the entity

```java
public record RegistrationRequest(@NotBlank String username, @NotBlank String password) { }
```

`@RequestBody AppUser` hands the client every column, `roles` included. A record with exactly the
fields the client may set makes over-posting structurally impossible, and the server assigns anything
privileged.

### File paths: canonicalise, then check containment

```java
Path base = baseDir.toRealPath();
Path target = base.resolve(name).normalize();
if (!target.startsWith(base)) throw new ResponseStatusException(BAD_REQUEST, "Invalid file name");
```

Blacklisting `".."` loses to `%2e%2e%2f`, `....//` and absolute paths. `resolve()` on an absolute input
silently discards the base, which is why the containment check has to come after `normalize()`.

### Redirect targets: relative, or allowlisted host

```java
if (target.startsWith("/")) return !target.startsWith("//");   // // is protocol-relative
return allowedHosts.contains(new URI(target).getHost().toLowerCase(Locale.ROOT));
```

Compare the host of a parsed `URI`; `startsWith` on the raw string is defeated by
`https://trusted.example.evil.test`.

### Outbound URLs: allowlist, re-check after DNS, no redirects

```java
HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
```

Scheme allowlist (`http`/`https`), host allowlist, then verify the *resolved* address is not loopback,
link-local, site-local, any-local or multicast. Skipping the address check leaves DNS rebinding open;
following redirects lets an allowlisted host hand you `http://169.254.169.254/`.

### XML: no DOCTYPE

```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
factory.setXIncludeAware(false);
```

Insecure by default in every JAXP factory. Centralise parsing in one hardened component rather than
configuring it per call site.

---

## Shaping responses

Return DTOs, not entities. The response then contains exactly what is declared, so a column added to
the entity later cannot start leaking through an endpoint written before it existed.

```java
public record UserProfile(String username, List<String> roles) { }
```

Add `@JsonIgnore` to the credential as a second layer, and keep the error path quiet:

```properties
server.error.include-stacktrace=never
server.error.include-message=never
```

Failure responses must not distinguish "no such user" from "wrong password" — authenticate through the
`AuthenticationManager` and Spring Security's `hideUserNotFoundExceptions` default handles it for you.

---

## Keeping insecure demo code out of the application

Teaching repos that ship deliberately vulnerable examples have a trap worth knowing about. A
`Vulnerable*` class must be annotated `@Controller` for `MockMvcBuilders.standaloneSetup(...)` to
register its handler methods — and that also makes it a component-scan candidate, because `src/test` is
on the classpath while tests run. The insecure endpoints then join the very application the defense
tests are meant to probe.

Mark them and exclude them explicitly:

```java
@SpringBootApplication
@ComponentScan(excludeFilters = {
        @ComponentScan.Filter(type = FilterType.CUSTOM, classes = TypeExcludeFilter.class),
        @ComponentScan.Filter(type = FilterType.CUSTOM, classes = AutoConfigurationExcludeFilter.class),
        @ComponentScan.Filter(type = FilterType.ANNOTATION, classes = VulnerableExample.class)
})
public class SecurityApplication { }
```

Declaring `@ComponentScan` directly overrides the one meta-annotated on `@SpringBootApplication`, so
Boot's two default filters have to be restated — omitting them breaks test slices and pulls
auto-configuration classes in as ordinary beans. Then assert the boundary holds, so it cannot regress:

```java
assertThat(context.getBeansWithAnnotation(VulnerableExample.class)).isEmpty();
```

---

← Back to the [README](../README.md) · see also [attacks.md](attacks.md)
