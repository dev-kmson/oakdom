package io.oakdom.core.matcher;

import java.util.List;

public class UrlPatternMatcher {

    private final List<String> patterns;

    public UrlPatternMatcher(List<String> patterns) {
        this.patterns = patterns;
    }

    public boolean matches(String requestUri) {
        return false;
    }
}
