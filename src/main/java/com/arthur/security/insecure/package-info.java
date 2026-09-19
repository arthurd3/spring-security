/**
 * Deliberately insecure HTTP endpoints for the live attack lab - the code the shell scripts under
 * {@code scripts/} attack over real HTTP.
 *
 * <p><b>None of this ever runs unless you ask for it.</b> Every class here is annotated
 * {@code @Profile("insecure")}, so it is only wired into the application when it is started with the
 * {@code insecure} Spring profile active:
 *
 * <pre>{@code ./mvnw spring-boot:run -Dspring-boot.run.profiles=insecure}</pre>
 *
 * <p>In the default profile - which is what {@code ./mvnw test} and a plain {@code spring-boot:run}
 * use - none of these beans load and no {@code /vulnerable/**} route exists. That invariant is checked
 * by {@code VulnerableCodeIsolationTest}. The endpoints exist purely so a learner can watch the same
 * payload succeed here and be refused by the hardened {@code /api/**} endpoints, side by side.
 *
 * <p>Why a profile instead of {@code src/test}? The unit tests keep their own insecure fixtures under
 * {@code src/test} (never shipped). These profile-gated copies are what make the flaw reachable over
 * the network for the {@code scripts/} demos, without ever being active by accident.
 */
package com.arthur.security.insecure;
