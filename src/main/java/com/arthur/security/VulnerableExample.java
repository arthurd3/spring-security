package com.arthur.security;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a class as deliberately insecure teaching material that must never become a live bean.
 *
 * <p>Every {@code Vulnerable*} class in the {@code attacks} test packages carries this annotation, and
 * {@link SecurityApplication} excludes it from component scanning. Without the exclusion those classes
 * <i>are</i> picked up: they are annotated {@code @Controller} (which
 * {@code MockMvcBuilders.standaloneSetup} requires in order to register their handler methods), they
 * sit under the scanned {@code com.arthur.security} package, and {@code src/test} is on the classpath
 * while tests run - so an insecure endpoint would quietly join the very application under test.
 *
 * <p>These classes never ship: {@code src/test} is absent from the packaged jar, so
 * {@code spring-boot:run} cannot expose them either way. The exclusion is about keeping the
 * <i>integration tests</i> honest - a defense test must exercise the real attack surface, not one
 * with extra insecure endpoints bolted on. {@code VulnerableCodeIsolationTest} enforces this.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface VulnerableExample {
}
