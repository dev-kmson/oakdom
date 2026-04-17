package io.oakdom.xss.filter;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.core.matcher.UrlPatternMatcher;
import io.oakdom.web.filter.OakdomFilter;
import io.oakdom.xss.config.XssConfig;
import io.oakdom.xss.sanitizer.DefaultXssSanitizer;

import java.util.Collections;

/**
 * XSS-specific implementation of {@link OakdomFilter}.
 *
 * <p>Determines whether a request parameter should be excluded from XSS filtering,
 * and resolves the {@link FilterMode} to apply, based on the rules defined in
 * {@link XssConfig}.
 *
 * <h3>Usage — legacy Spring MVC</h3>
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
    private final DefaultXssSanitizer blacklistSanitizer;
    private final DefaultXssSanitizer whitelistSanitizer;

    /**
     * Creates a filter using the configuration returned by {@link #configure()}.
     * Intended for subclasses that override {@link #configure()}.
     */
    public OakdomXssFilter() {
        this.config = configure();
        this.blacklistSanitizer = DefaultXssSanitizer.of(FilterMode.BLACKLIST, this.config);
        this.whitelistSanitizer = DefaultXssSanitizer.of(FilterMode.WHITELIST, this.config);
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
        this.blacklistSanitizer = DefaultXssSanitizer.of(FilterMode.BLACKLIST, config);
        this.whitelistSanitizer = DefaultXssSanitizer.of(FilterMode.WHITELIST, config);
    }

    /**
     * Sanitizes the given value using the sanitizer configured for the specified
     * {@link FilterMode}.
     *
     * <p>The sanitizer reflects any customizations ({@code addEscapeChar},
     * {@code addAllowedTag}, etc.) defined in the {@link XssConfig} this filter
     * was constructed with.
     *
     * @param value      the raw input value; may be {@code null}
     * @param filterMode the filter mode to apply; must not be {@code null}
     * @return the sanitized value, or {@code null} if {@code value} is {@code null}
     */
    public String sanitize(String value, FilterMode filterMode) {
        return (filterMode == FilterMode.WHITELIST ? whitelistSanitizer : blacklistSanitizer).sanitize(value);
    }

    /**
     * Returns the {@link XssConfig} to use for this filter.
     *
     * <p>Subclasses can override this method to provide custom configuration
     * instead of passing a config to the constructor. The default implementation
     * returns a config with {@link FilterMode#BLACKLIST} as the global mode.
     *
     * <p><strong>Note:</strong> This method is called from the constructor.
     * Implementations must not reference subclass instance fields, as they will
     * not yet be initialized at the time this method is invoked.
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
