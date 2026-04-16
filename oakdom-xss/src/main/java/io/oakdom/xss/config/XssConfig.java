package io.oakdom.xss.config;

import io.oakdom.core.filter.FilterMode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Configuration for oakdom XSS filtering.
 *
 * <p>Defines the global filter mode, per-URL/parameter filter-mode overrides,
 * and per-URL/parameter exclusion rules. Priority order (highest to lowest):
 * <ol>
 *   <li>Parameter-level rule (filter or exclude)</li>
 *   <li>URL-level rule (filter or exclude)</li>
 *   <li>Global filter mode</li>
 * </ol>
 *
 * <p>Use {@link Builder} to construct an instance programmatically:
 * <pre>{@code
 * XssConfig config = XssConfig.builder()
 *     .globalFilterMode(FilterMode.BLACKLIST)
 *     .filterRule("/api/editor", "htmlContent", FilterMode.WHITELIST)
 *     .excludeRule("/api/raw", null)
 *     .build();
 * }</pre>
 */
public class XssConfig {

    private final FilterMode globalFilterMode;
    private final List<FilterRule> filterRules;
    private final List<ExcludeRule> excludeRules;

    private XssConfig(Builder builder) {
        this.globalFilterMode = builder.globalFilterMode;
        this.filterRules = Collections.unmodifiableList(new ArrayList<>(builder.filterRules));
        this.excludeRules = Collections.unmodifiableList(new ArrayList<>(builder.excludeRules));
    }

    /**
     * Returns the global (default) filter mode applied when no matching rule is found.
     *
     * @return global filter mode; never {@code null}
     */
    public FilterMode getGlobalFilterMode() {
        return globalFilterMode;
    }

    /**
     * Returns the list of filter-mode override rules.
     *
     * @return unmodifiable list of filter rules; never {@code null}
     */
    public List<FilterRule> getFilterRules() {
        return filterRules;
    }

    /**
     * Returns the list of exclusion rules (parameters/URLs that skip filtering entirely).
     *
     * @return unmodifiable list of exclude rules; never {@code null}
     */
    public List<ExcludeRule> getExcludeRules() {
        return excludeRules;
    }

    /**
     * Creates a new {@link Builder} with {@link FilterMode#BLACKLIST} as the default global mode.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    // -------------------------------------------------------------------------
    // Nested types
    // -------------------------------------------------------------------------

    /**
     * A rule that overrides the filter mode for a specific URL pattern and/or parameter name.
     *
     * <p>Either {@code urlPattern} or {@code parameterName} may be {@code null}, but not both.
     * When both are set, the rule matches only when both the URL and parameter name match.
     */
    public static class FilterRule {

        private final String urlPattern;
        private final String parameterName;
        private final FilterMode filterMode;

        /**
         * Constructs a filter rule.
         *
         * @param urlPattern    Ant-style URL pattern, or {@code null} to match any URL
         * @param parameterName exact parameter name, or {@code null} to match any parameter
         * @param filterMode    the filter mode to apply when this rule matches; must not be {@code null}
         */
        public FilterRule(String urlPattern, String parameterName, FilterMode filterMode) {
            if (filterMode == null) {
                throw new IllegalArgumentException("filterMode must not be null");
            }
            this.urlPattern = urlPattern;
            this.parameterName = parameterName;
            this.filterMode = filterMode;
        }

        /**
         * Returns the Ant-style URL pattern, or {@code null} if this rule applies to any URL.
         *
         * @return URL pattern or {@code null}
         */
        public String getUrlPattern() {
            return urlPattern;
        }

        /**
         * Returns the exact parameter name, or {@code null} if this rule applies to any parameter.
         *
         * @return parameter name or {@code null}
         */
        public String getParameterName() {
            return parameterName;
        }

        /**
         * Returns the filter mode applied when this rule matches.
         *
         * @return filter mode; never {@code null}
         */
        public FilterMode getFilterMode() {
            return filterMode;
        }
    }

    /**
     * A rule that excludes a specific URL pattern and/or parameter name from XSS filtering entirely.
     *
     * <p>Either {@code urlPattern} or {@code parameterName} may be {@code null}, but not both.
     * When both are set, filtering is skipped only when both the URL and parameter name match.
     */
    public static class ExcludeRule {

        private final String urlPattern;
        private final String parameterName;

        /**
         * Constructs an exclude rule.
         *
         * @param urlPattern    Ant-style URL pattern, or {@code null} to match any URL
         * @param parameterName exact parameter name, or {@code null} to match any parameter
         */
        public ExcludeRule(String urlPattern, String parameterName) {
            this.urlPattern = urlPattern;
            this.parameterName = parameterName;
        }

        /**
         * Returns the Ant-style URL pattern, or {@code null} if this rule applies to any URL.
         *
         * @return URL pattern or {@code null}
         */
        public String getUrlPattern() {
            return urlPattern;
        }

        /**
         * Returns the exact parameter name, or {@code null} if this rule applies to any parameter.
         *
         * @return parameter name or {@code null}
         */
        public String getParameterName() {
            return parameterName;
        }
    }

    // -------------------------------------------------------------------------
    // Builder
    // -------------------------------------------------------------------------

    /**
     * Builder for {@link XssConfig}.
     */
    public static class Builder {

        private FilterMode globalFilterMode = FilterMode.BLACKLIST;
        private final List<FilterRule> filterRules = new ArrayList<>();
        private final List<ExcludeRule> excludeRules = new ArrayList<>();

        private Builder() {
        }

        /**
         * Sets the global (default) filter mode.
         * Defaults to {@link FilterMode#BLACKLIST} if not specified.
         *
         * @param globalFilterMode the global filter mode; must not be {@code null}
         * @return this builder
         */
        public Builder globalFilterMode(FilterMode globalFilterMode) {
            if (globalFilterMode == null) {
                throw new IllegalArgumentException("globalFilterMode must not be null");
            }
            this.globalFilterMode = globalFilterMode;
            return this;
        }

        /**
         * Adds a filter-mode override rule for the given URL pattern and/or parameter name.
         *
         * @param urlPattern    Ant-style URL pattern, or {@code null} to match any URL
         * @param parameterName exact parameter name, or {@code null} to match any parameter
         * @param filterMode    the filter mode to apply; must not be {@code null}
         * @return this builder
         */
        public Builder filterRule(String urlPattern, String parameterName, FilterMode filterMode) {
            filterRules.add(new FilterRule(urlPattern, parameterName, filterMode));
            return this;
        }

        /**
         * Adds an exclusion rule for the given URL pattern and/or parameter name.
         * Requests matching this rule will skip XSS filtering entirely.
         *
         * @param urlPattern    Ant-style URL pattern, or {@code null} to match any URL
         * @param parameterName exact parameter name, or {@code null} to match any parameter
         * @return this builder
         */
        public Builder excludeRule(String urlPattern, String parameterName) {
            excludeRules.add(new ExcludeRule(urlPattern, parameterName));
            return this;
        }

        /**
         * Builds and returns the {@link XssConfig} instance.
         *
         * @return configured {@link XssConfig}
         */
        public XssConfig build() {
            return new XssConfig(this);
        }
    }
}
