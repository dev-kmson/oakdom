package io.oakdom.web.wrapper;

import io.oakdom.core.filter.FilterMode;

/**
 * Abstract base class for oakdom HTTP request wrappers.
 *
 * <p>Implementations wrap the original HTTP request and intercept parameter access
 * to apply sanitization transparently. The actual servlet-specific wrapping
 * (e.g., extending {@code HttpServletRequestWrapper}) is done in subclasses.
 */
public abstract class OakdomRequestWrapper {

    /**
     * Sanitizes the given value according to the specified {@link FilterMode}.
     *
     * @param value      the raw input value
     * @param filterMode the filter mode to apply
     * @return the sanitized value
     */
    public abstract String sanitizeValue(String value, FilterMode filterMode);

    /**
     * Returns {@code true} if the given parameter should be excluded from sanitization.
     *
     * @param parameterName the parameter name to check
     * @return {@code true} if the parameter is excluded
     */
    public abstract boolean isExcluded(String parameterName);
}
