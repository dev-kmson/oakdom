package io.oakdom.core.matcher;

import java.util.List;

public class ParameterMatcher {

    private final List<String> excludedParameters;

    public ParameterMatcher(List<String> excludedParameters) {
        this.excludedParameters = excludedParameters;
    }

    public boolean isExcluded(String parameterName) {
        return false;
    }
}
