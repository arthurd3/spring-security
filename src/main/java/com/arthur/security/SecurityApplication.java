package com.arthur.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.TypeExcludeFilter;
import org.springframework.boot.autoconfigure.AutoConfigurationExcludeFilter;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;

/**
 * Application entry point.
 *
 * <p>The explicit {@code @ComponentScan} exists only to add the {@link VulnerableExample} exclusion.
 * Declaring {@code @ComponentScan} directly overrides the one meta-annotated on
 * {@code @SpringBootApplication}, so the two filters Spring Boot installs by default
 * ({@link TypeExcludeFilter} and {@link AutoConfigurationExcludeFilter}) are restated here - dropping
 * them would break test slices and pull auto-configuration classes in as ordinary beans.
 */
@SpringBootApplication
@ComponentScan(excludeFilters = {
        @ComponentScan.Filter(type = FilterType.CUSTOM, classes = TypeExcludeFilter.class),
        @ComponentScan.Filter(type = FilterType.CUSTOM, classes = AutoConfigurationExcludeFilter.class),
        @ComponentScan.Filter(type = FilterType.ANNOTATION, classes = VulnerableExample.class)
})
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

}
