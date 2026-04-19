package io.oakdom.xss.autoconfigure;

import io.oakdom.xss.interceptor.OakdomXssAnnotationInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Registers {@link OakdomXssAnnotationInterceptor} in the Spring MVC interceptor chain.
 *
 * <p>This configurer is registered automatically by {@link XssAutoConfiguration} in
 * Spring Boot 3.x web applications. It ensures that XSS-related annotations
 * ({@code @OakdomXssExclude}, {@code @OakdomXssFilterMode}) placed on controller
 * handler methods are resolved before request parameters or the request body are read.
 *
 * <p>This variant targets {@code jakarta.servlet} environments (Spring Boot 3.x).
 */
public class OakdomXssMvcConfigurer implements WebMvcConfigurer {

    /**
     * Adds {@link OakdomXssAnnotationInterceptor} to the interceptor registry so
     * that handler-method annotations are processed on every request.
     *
     * @param registry the interceptor registry
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new OakdomXssAnnotationInterceptor());
    }
}
