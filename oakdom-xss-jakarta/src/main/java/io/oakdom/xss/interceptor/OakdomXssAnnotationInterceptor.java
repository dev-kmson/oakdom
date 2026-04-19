package io.oakdom.xss.interceptor;

import io.oakdom.xss.annotation.OakdomXssExclude;
import io.oakdom.xss.annotation.OakdomXssFilterMode;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Spring MVC interceptor that reads {@link OakdomXssExclude} and
 * {@link OakdomXssFilterMode} annotations from controller handler methods and
 * stores the resolved settings in request attributes for use by
 * {@link io.oakdom.xss.filter.OakdomXssFilter}.
 *
 * <p>This interceptor must run before Spring MVC reads request parameters or
 * the request body. Since the filter wraps the request lazily, this is always
 * satisfied as long as the interceptor is registered in the Spring MVC
 * interceptor chain.
 *
 * <p>This variant targets {@code jakarta.servlet} environments (Tomcat 10+).
 *
 * <h3>Annotation priority (highest to lowest)</h3>
 * <ol>
 *   <li>Parameter-level annotation on {@code @RequestParam} or {@code @RequestBody}</li>
 *   <li>Method-level annotation</li>
 *   <li>Configuration-based rules ({@code XssConfig})</li>
 *   <li>Global filter mode</li>
 * </ol>
 *
 * <h3>Usage</h3>
 * <p>Register this interceptor in your Spring MVC configuration:
 * <pre>{@code
 * &#64;Configuration
 * public class WebConfig implements WebMvcConfigurer {
 *     &#64;Override
 *     public void addInterceptors(InterceptorRegistry registry) {
 *         registry.addInterceptor(new OakdomXssAnnotationInterceptor());
 *     }
 * }
 * }</pre>
 *
 * <p>When using {@code oakdom-xss-spring-boot3-starter}, this interceptor is
 * registered automatically — no manual configuration required.
 */
public class OakdomXssAnnotationInterceptor implements HandlerInterceptor {

    private static final DefaultParameterNameDiscoverer PARAM_NAME_DISCOVERER =
            new DefaultParameterNameDiscoverer();

    /**
     * Reads XSS annotations from the handler method and stores the results in
     * request attributes so that the XSS filter wrapper can apply them when
     * parameters or the request body are accessed.
     *
     * @param request  the current request
     * @param response the current response
     * @param handler  the chosen handler to execute, for type and/or instance evaluation
     * @return {@code true} always — this interceptor never blocks the request
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }
        HandlerMethod handlerMethod = (HandlerMethod) handler;

        // Method-level @OakdomXssExclude — exclude all parameters and body
        OakdomXssExclude methodExclude = handlerMethod.getMethodAnnotation(OakdomXssExclude.class);
        if (methodExclude != null) {
            request.setAttribute(OakdomXssRequestAttributes.EXCLUDE_ALL, Boolean.TRUE);
            return true;
        }

        // Method-level @OakdomXssFilterMode — default mode for all parameters and body
        OakdomXssFilterMode methodMode = handlerMethod.getMethodAnnotation(OakdomXssFilterMode.class);
        if (methodMode != null) {
            request.setAttribute(OakdomXssRequestAttributes.METHOD_MODE, methodMode.value());
        }

        // Parameter-level annotations
        for (MethodParameter param : handlerMethod.getMethodParameters()) {
            OakdomXssExclude paramExclude = param.getParameterAnnotation(OakdomXssExclude.class);
            OakdomXssFilterMode paramMode = param.getParameterAnnotation(OakdomXssFilterMode.class);

            // @RequestBody parameter — always capture DTO class for field annotation processing
            if (param.hasParameterAnnotation(RequestBody.class)) {
                request.setAttribute(OakdomXssRequestAttributes.BODY_DTO_CLASS, param.getParameterType());
                if (paramExclude != null) {
                    request.setAttribute(OakdomXssRequestAttributes.BODY_EXCLUDE, Boolean.TRUE);
                }
                if (paramMode != null) {
                    request.setAttribute(OakdomXssRequestAttributes.BODY_MODE, paramMode.value());
                }
                continue;
            }

            if (paramExclude == null && paramMode == null) {
                continue;
            }

            // @RequestParam or plain parameter — controls that HTTP parameter
            String httpParamName = resolveHttpParamName(param);
            if (httpParamName == null) {
                continue;
            }
            if (paramExclude != null) {
                request.setAttribute(OakdomXssRequestAttributes.PARAM_EXCLUDE_PREFIX + httpParamName, Boolean.TRUE);
            }
            if (paramMode != null) {
                request.setAttribute(OakdomXssRequestAttributes.PARAM_MODE_PREFIX + httpParamName, paramMode.value());
            }
        }

        return true;
    }

    private String resolveHttpParamName(MethodParameter param) {
        RequestParam requestParam = param.getParameterAnnotation(RequestParam.class);
        if (requestParam != null) {
            if (!requestParam.value().isEmpty()) {
                return requestParam.value();
            }
            if (!requestParam.name().isEmpty()) {
                return requestParam.name();
            }
        }
        param.initParameterNameDiscovery(PARAM_NAME_DISCOVERER);
        return param.getParameterName();
    }
}
