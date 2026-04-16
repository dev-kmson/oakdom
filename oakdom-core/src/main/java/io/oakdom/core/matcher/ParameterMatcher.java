package io.oakdom.core.matcher;

import java.util.List;

/**
 * Determines whether a request parameter should be excluded from filtering.
 *
 * <p>Parameter names are matched using case-sensitive exact comparison.
 */
public class ParameterMatcher {

    private final List<String> excludedParameters;

    /**
     * Creates a new matcher with the given list of parameter names to exclude.
     *
     * @param excludedParameters the list of parameter names to exclude from filtering
     */
    public ParameterMatcher(List<String> excludedParameters) {
        this.excludedParameters = excludedParameters;
    }

    /**
     * Returns {@code true} if the given parameter name is in the exclusion list.
     *
     * @param parameterName the parameter name to check
     * @return {@code true} if the parameter should be excluded, {@code false} otherwise
     */
    public boolean isExcluded(String parameterName) {
        if (parameterName == null) {
            return false;
        }
        for (String excluded : excludedParameters) {
            if (excluded.equals(parameterName)) {
                return true;
            }
        }
        return false;
    }
}
