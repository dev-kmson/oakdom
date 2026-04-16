package io.oakdom.core.matcher;

import java.util.List;

public class ParameterMatcher {

    private final List<String> excludedParameters;

    public ParameterMatcher(List<String> excludedParameters) {
        this.excludedParameters = excludedParameters;
    }

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
