package io.oakdom.xss.wrapper;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.web.filter.OakdomFilter;
import io.oakdom.web.wrapper.OakdomRequestWrapper;
import io.oakdom.xss.sanitizer.DefaultXssSanitizer;

/**
 * XSS-specific implementation of {@link OakdomRequestWrapper}.
 *
 * <p>Sanitizes parameter values using {@link DefaultXssSanitizer} and delegates
 * exclusion checks to the configured {@link OakdomFilter}.
 *
 * <p>This class acts as a strategy object used by the XSS servlet filter to
 * apply sanitization when parameter values are accessed:
 * <pre>{@code
 * OakdomXssRequestWrapper wrapper = new OakdomXssRequestWrapper(filter, request.getRequestURI());
 *
 * // Check exclusion before accessing the value
 * if (!wrapper.isExcluded(paramName)) {
 *     FilterMode mode = filter.resolveFilterMode(requestUri, paramName);
 *     String sanitized = wrapper.sanitizeValue(rawValue, mode);
 * }
 * }</pre>
 */
public class OakdomXssRequestWrapper extends OakdomRequestWrapper {

    private final OakdomFilter filter;
    private final String requestUri;

    /**
     * Creates a wrapper for the given filter and request URI.
     *
     * @param filter     the filter used to determine exclusion; must not be {@code null}
     * @param requestUri the URI of the current request
     */
    public OakdomXssRequestWrapper(OakdomFilter filter, String requestUri) {
        if (filter == null) {
            throw new IllegalArgumentException("filter must not be null");
        }
        this.filter = filter;
        this.requestUri = requestUri;
    }

    /**
     * Sanitizes the given value using the {@link DefaultXssSanitizer} for the
     * specified {@link FilterMode}.
     *
     * @param value      the raw input value; may be {@code null}
     * @param filterMode the filter mode to apply; must not be {@code null}
     * @return the sanitized value, or {@code null} if {@code value} is {@code null}
     */
    @Override
    public String sanitizeValue(String value, FilterMode filterMode) {
        return DefaultXssSanitizer.of(filterMode).sanitize(value);
    }

    /**
     * Returns {@code true} if the given parameter should be excluded from XSS filtering.
     *
     * <p>Delegates to {@link OakdomFilter#shouldSkip(String, String)} using the
     * request URI provided at construction time.
     *
     * @param parameterName the parameter name to check
     * @return {@code true} if the parameter is excluded from filtering
     */
    @Override
    public boolean isExcluded(String parameterName) {
        return filter.shouldSkip(requestUri, parameterName);
    }
}
