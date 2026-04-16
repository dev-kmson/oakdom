package io.oakdom.xss.filter;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.core.matcher.UrlPatternMatcher;
import io.oakdom.web.filter.OakdomFilter;
import io.oakdom.xss.config.XssConfig;

import java.util.Collections;

/**
 * XSS-specific implementation of {@link OakdomFilter}.
 *
 * <p>Determines whether a request parameter should be excluded from XSS filtering,
 * and resolves the {@link FilterMode} to apply, based on the rules defined in
 * {@link XssConfig}.
 *
 * <h3>Usage — legacy Spring MVC (subclass)</h3>
 * <p>Extend this class and override {@link #configure()} to provide a custom
 * {@link XssConfig}. Register the subclass as a servlet filter in {@code web.xml}:
 * <pre>{@code
 * public class MyXssFilter extends OakdomXssFilter {
 *     @Override
 *     protected XssConfig configure() {
 *         return XssConfig.builder()
 *             .globalFilterMode(FilterMode.BLACKLIST)
 *             .filterRule("/api/editor/**", "content", FilterMode.WHITELIST)
 *             .build();
 *     }
 * }
 * }</pre>
 *
 * <h3>Usage — programmatic</h3>
 * <pre>{@code
 * OakdomXssFilter filter = new OakdomXssFilter(
 *     XssConfig.builder().globalFilterMode(FilterMode.BLACKLIST).build()
 * );
 * }</pre>
 *
 * <h3>Filter mode priority</h3>
 * <ol>
 *   <li>Rule matching both URL pattern and parameter name (most specific)</li>
 *   <li>Rule matching parameter name only</li>
 *   <li>Rule matching URL pattern only</li>
 *   <li>Global filter mode (least specific)</li>
 * </ol>
 */
public class OakdomXssFilter implements OakdomFilter {

    private final XssConfig config;

    /**
     * Creates a filter using the configuration returned by {@link #configure()}.
     * Intended for subclasses that override {@link #configure()}.
     */
    public OakdomXssFilter() {
        this.config = configure();
    }

    /**
     * Creates a filter with the given configuration.
     *
     * @param config the XSS configuration to use; must not be {@code null}
     */
    public OakdomXssFilter(XssConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("config must not be null");
        }
        this.config = config;
    }

    /**
     * Returns the {@link XssConfig} to use for this filter.
     *
     * <p>Subclasses can override this method to provide custom configuration
     * instead of passing a config to the constructor. The default implementation
     * returns a config with {@link FilterMode#BLACKLIST} as the global mode.
     *
     * @return the XSS configuration; never {@code null}
     */
    protected XssConfig configure() {
        return XssConfig.builder().build();
    }

    /**
     * Returns {@code true} if the given request URI and parameter combination
     * matches any of the configured exclude rules.
     *
     * <p>A rule with both a URL pattern and a parameter name matches only when
     * both conditions are satisfied. A rule with only a URL pattern matches any
     * parameter on that URL. A rule with only a parameter name matches that
     * parameter on any URL.
     *
     * @param requestUri    the request URI
     * @param parameterName the parameter name
     * @return {@code true} if filtering should be skipped
     */
    @Override
    public boolean shouldSkip(String requestUri, String parameterName) {
        for (XssConfig.ExcludeRule rule : config.getExcludeRules()) {
            if (matchesExcludeRule(rule, requestUri, parameterName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Resolves the {@link FilterMode} for the given request URI and parameter name
     * by evaluating the configured filter rules in priority order.
     *
     * @param requestUri    the request URI
     * @param parameterName the parameter name
     * @return the resolved {@link FilterMode}; never {@code null}
     */
    @Override
    public FilterMode resolveFilterMode(String requestUri, String parameterName) {
        // Priority 1: rule matching both URL pattern and parameter name
        for (XssConfig.FilterRule rule : config.getFilterRules()) {
            if (rule.getUrlPattern() != null && rule.getParameterName() != null) {
                if (matchesUrl(rule.getUrlPattern(), requestUri)
                        && matchesParameter(rule.getParameterName(), parameterName)) {
                    return rule.getFilterMode();
                }
            }
        }
        // Priority 2: rule matching parameter name only (applies to any URL)
        for (XssConfig.FilterRule rule : config.getFilterRules()) {
            if (rule.getUrlPattern() == null && rule.getParameterName() != null) {
                if (matchesParameter(rule.getParameterName(), parameterName)) {
                    return rule.getFilterMode();
                }
            }
        }
        // Priority 3: rule matching URL pattern only (applies to any parameter)
        for (XssConfig.FilterRule rule : config.getFilterRules()) {
            if (rule.getUrlPattern() != null && rule.getParameterName() == null) {
                if (matchesUrl(rule.getUrlPattern(), requestUri)) {
                    return rule.getFilterMode();
                }
            }
        }
        return config.getGlobalFilterMode();
    }

    private boolean matchesExcludeRule(XssConfig.ExcludeRule rule, String requestUri, String parameterName) {
        String urlPattern = rule.getUrlPattern();
        String paramName = rule.getParameterName();

        if (urlPattern != null && paramName != null) {
            return matchesUrl(urlPattern, requestUri) && matchesParameter(paramName, parameterName);
        }
        if (urlPattern != null) {
            return matchesUrl(urlPattern, requestUri);
        }
        if (paramName != null) {
            return matchesParameter(paramName, parameterName);
        }
        return false;
    }

    private boolean matchesUrl(String pattern, String requestUri) {
        if (requestUri == null) {
            return false;
        }
        return new UrlPatternMatcher(Collections.singletonList(pattern)).matches(requestUri);
    }

    private boolean matchesParameter(String paramName, String parameterName) {
        return paramName.equals(parameterName);
    }
}
