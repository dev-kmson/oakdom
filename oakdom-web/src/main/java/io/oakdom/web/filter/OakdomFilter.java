package io.oakdom.web.filter;

import io.oakdom.core.filter.FilterMode;

/**
 * Common contract for all oakdom security filters.
 *
 * <p>Implementations determine whether a given request should be skipped entirely,
 * and which {@link FilterMode} should be applied based on the request URI and parameter name.
 *
 * <p>Priority order for filter mode resolution: parameter-level &gt; URL-level &gt; global.
 */
public interface OakdomFilter {

    /**
     * Returns {@code true} if the given request URI and parameter combination
     * should be excluded from filtering entirely.
     *
     * @param requestUri    the request URI
     * @param parameterName the parameter name, or {@code null} to check at the URL level
     * @return {@code true} if filtering should be skipped
     */
    boolean shouldSkip(String requestUri, String parameterName);

    /**
     * Resolves the {@link FilterMode} to apply for the given request URI and parameter.
     *
     * <p>Parameter-level rules take precedence over URL-level rules,
     * which take precedence over the global filter mode.
     *
     * @param requestUri    the request URI
     * @param parameterName the parameter name, or {@code null} to resolve at the URL level
     * @return the resolved {@link FilterMode}
     */
    FilterMode resolveFilterMode(String requestUri, String parameterName);
}
