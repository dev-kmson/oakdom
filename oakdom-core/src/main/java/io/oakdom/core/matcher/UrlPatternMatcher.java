package io.oakdom.core.matcher;

import java.util.List;

/**
 * Matches request URIs against a list of Ant-style URL patterns.
 *
 * <p>Supported pattern syntax:
 * <ul>
 *   <li>{@code ?} - matches exactly one character</li>
 *   <li>{@code *} - matches zero or more characters within a single path segment</li>
 *   <li>{@code **} - matches zero or more path segments</li>
 * </ul>
 *
 * <p>Example patterns: {@code /api/editor/**}, {@code /admin/*}, {@code /user/?/profile}
 */
public class UrlPatternMatcher {

    private final List<String> patterns;

    /**
     * Creates a new matcher with the given list of URL patterns.
     *
     * @param patterns the list of Ant-style URL patterns to match against
     */
    public UrlPatternMatcher(List<String> patterns) {
        this.patterns = patterns;
    }

    /**
     * Returns {@code true} if the given request URI matches any of the configured patterns.
     *
     * @param requestUri the request URI to test (without query string)
     * @return {@code true} if a matching pattern is found, {@code false} otherwise
     */
    public boolean matches(String requestUri) {
        for (String pattern : patterns) {
            if (matchPattern(pattern, requestUri)) {
                return true;
            }
        }
        return false;
    }

    private boolean matchPattern(String pattern, String path) {
        String[] patternParts = pattern.split("/", -1);
        String[] pathParts = path.split("/", -1);
        return matchParts(patternParts, 0, pathParts, 0);
    }

    private boolean matchParts(String[] patternParts, int pi, String[] pathParts, int si) {
        while (pi < patternParts.length && si < pathParts.length) {
            String p = patternParts[pi];
            if ("**".equals(p)) {
                if (pi == patternParts.length - 1) {
                    return true;
                }
                for (int i = si; i <= pathParts.length; i++) {
                    if (matchParts(patternParts, pi + 1, pathParts, i)) {
                        return true;
                    }
                }
                return false;
            }
            if (!matchSegment(p, pathParts[si])) {
                return false;
            }
            pi++;
            si++;
        }
        while (pi < patternParts.length && "**".equals(patternParts[pi])) {
            pi++;
        }
        return pi == patternParts.length && si == pathParts.length;
    }

    private boolean matchSegment(String pattern, String segment) {
        return matchSegmentChars(pattern, 0, segment, 0);
    }

    private boolean matchSegmentChars(String pattern, int pi, String segment, int si) {
        while (pi < pattern.length() && si < segment.length()) {
            char p = pattern.charAt(pi);
            if (p == '*') {
                if (pi == pattern.length() - 1) {
                    return true;
                }
                for (int i = si; i <= segment.length(); i++) {
                    if (matchSegmentChars(pattern, pi + 1, segment, i)) {
                        return true;
                    }
                }
                return false;
            }
            if (p != '?' && p != segment.charAt(si)) {
                return false;
            }
            pi++;
            si++;
        }
        while (pi < pattern.length() && pattern.charAt(pi) == '*') {
            pi++;
        }
        return pi == pattern.length() && si == segment.length();
    }
}
