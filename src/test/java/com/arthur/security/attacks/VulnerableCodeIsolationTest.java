package com.arthur.security.attacks;

import com.arthur.security.VulnerableExample;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the boundary the whole lab rests on: the intentionally insecure example code must never
 * become part of the application the defense tests exercise.
 *
 * <p>This is not theoretical. The {@code Vulnerable*} controllers must be annotated {@code @Controller}
 * for {@code MockMvcBuilders.standaloneSetup} to register their handler methods, they live under the
 * component-scanned {@code com.arthur.security} package, and {@code src/test} is on the classpath
 * while tests run. Without the {@link VulnerableExample} exclude filter in {@code SecurityApplication}
 * they are all picked up as live beans, and a "defense" test would be probing an application with
 * extra insecure endpoints bolted onto it.
 */
class VulnerableCodeIsolationTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Isolamento do Codigo Inseguro";

    @Autowired
    private ApplicationContext context;

    @Autowired
    private RequestMappingHandlerMapping handlerMapping;

    @Test
    @DisplayName("DEFENSE: no @VulnerableExample class is registered as a bean")
    void noVulnerableBeansInContext() {
        assertThat(context.getBeansWithAnnotation(VulnerableExample.class))
                .as("the exclude filter in SecurityApplication must keep these out of the context")
                .isEmpty();

        SecurityReport.defended(CATEGORY, "beans anotados com @VulnerableExample",
                "0 no contexto - excludeFilter do component scan ativo");
    }

    @Test
    @DisplayName("DEFENSE: no /vulnerable/** route exists in the real application")
    void noVulnerableRoutesAreMapped() {
        List<String> vulnerableRoutes = handlerMapping.getHandlerMethods().keySet().stream()
                .map(RequestMappingInfo::getPathPatternsCondition)
                .filter(java.util.Objects::nonNull)
                .flatMap(condition -> condition.getPatternValues().stream())
                .filter(pattern -> pattern.startsWith("/vulnerable"))
                .toList();

        assertThat(vulnerableRoutes)
                .as("insecure demo endpoints must not be routable in the application under test")
                .isEmpty();

        SecurityReport.defended(CATEGORY, "rotas /vulnerable/** mapeadas",
                "0 rotas - superficie de ataque real permanece intacta");
    }
}
