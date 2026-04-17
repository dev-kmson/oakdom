package io.oakdom.xss.config;

import io.oakdom.core.filter.FilterMode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Configuration for oakdom XSS filtering.
 *
 * <p>Defines the global filter mode, per-URL/parameter filter-mode overrides,
 * per-URL/parameter exclusion rules, and optional customizations to the default
 * blacklist escape character set and whitelist allowed tags/CSS properties.
 *
 * <p>Priority order for filter mode resolution (highest to lowest):
 * <ol>
 *   <li>Rule matching both URL pattern and parameter name (most specific)</li>
 *   <li>Rule matching parameter name only</li>
 *   <li>Rule matching URL pattern only</li>
 *   <li>Global filter mode (least specific)</li>
 * </ol>
 *
 * <p>Use {@link Builder} to construct an instance:
 * <pre>{@code
 * XssConfig config = XssConfig.builder()
 *     .globalFilterMode(FilterMode.WHITELIST)
 *     .filterRule("/api/editor/**", "content", FilterMode.WHITELIST)
 *     .excludeRule("/api/raw", null)
 *     .addAllowedTag("video", "audio")
 *     .removeAllowedTag("strike")
 *     .addAllowedCssProperty("line-height")
 *     .build();
 * }</pre>
 */
public class XssConfig {

    private final FilterMode globalFilterMode;
    private final List<FilterRule> filterRules;
    private final List<ExcludeRule> excludeRules;

    private final Set<Character> addEscapeChars;
    private final Set<Character> removeEscapeChars;
    private final Set<String> addAllowedTags;
    private final Set<String> removeAllowedTags;
    private final Set<String> addAllowedCssProperties;
    private final Set<String> removeAllowedCssProperties;

    private XssConfig(Builder builder) {
        this.globalFilterMode = builder.globalFilterMode;
        this.filterRules = Collections.unmodifiableList(new ArrayList<>(builder.filterRules));
        this.excludeRules = Collections.unmodifiableList(new ArrayList<>(builder.excludeRules));
        this.addEscapeChars = Collections.unmodifiableSet(new LinkedHashSet<>(builder.addEscapeChars));
        this.removeEscapeChars = Collections.unmodifiableSet(new LinkedHashSet<>(builder.removeEscapeChars));
        this.addAllowedTags = Collections.unmodifiableSet(new LinkedHashSet<>(builder.addAllowedTags));
        this.removeAllowedTags = Collections.unmodifiableSet(new LinkedHashSet<>(builder.removeAllowedTags));
        this.addAllowedCssProperties = Collections.unmodifiableSet(new LinkedHashSet<>(builder.addAllowedCssProperties));
        this.removeAllowedCssProperties = Collections.unmodifiableSet(new LinkedHashSet<>(builder.removeAllowedCssProperties));
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
     * Returns the characters to add to the blacklist escape set beyond the five defaults.
     *
     * @return unmodifiable set of characters to add; never {@code null}
     */
    public Set<Character> getAddEscapeChars() {
        return addEscapeChars;
    }

    /**
     * Returns the characters to remove from the blacklist default escape set.
     *
     * @return unmodifiable set of characters to remove; never {@code null}
     */
    public Set<Character> getRemoveEscapeChars() {
        return removeEscapeChars;
    }

    /**
     * Returns the HTML tags to add to the whitelist default allowed tag set.
     *
     * @return unmodifiable set of tag names to add; never {@code null}
     */
    public Set<String> getAddAllowedTags() {
        return addAllowedTags;
    }

    /**
     * Returns the HTML tags to remove from the whitelist default allowed tag set.
     *
     * @return unmodifiable set of tag names to remove; never {@code null}
     */
    public Set<String> getRemoveAllowedTags() {
        return removeAllowedTags;
    }

    /**
     * Returns the CSS properties to add to the whitelist default allowed CSS property set.
     *
     * @return unmodifiable set of CSS property names to add; never {@code null}
     */
    public Set<String> getAddAllowedCssProperties() {
        return addAllowedCssProperties;
    }

    /**
     * Returns the CSS properties to remove from the whitelist default allowed CSS property set.
     *
     * @return unmodifiable set of CSS property names to remove; never {@code null}
     */
    public Set<String> getRemoveAllowedCssProperties() {
        return removeAllowedCssProperties;
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

        private final Set<Character> addEscapeChars = new LinkedHashSet<>();
        private final Set<Character> removeEscapeChars = new LinkedHashSet<>();
        private final Set<String> addAllowedTags = new LinkedHashSet<>();
        private final Set<String> removeAllowedTags = new LinkedHashSet<>();
        private final Set<String> addAllowedCssProperties = new LinkedHashSet<>();
        private final Set<String> removeAllowedCssProperties = new LinkedHashSet<>();

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
         * Adds a filter-mode override rule that applies to all parameters under the
         * given URL pattern.
         *
         * @param urlPattern Ant-style URL pattern; must not be {@code null}
         * @param filterMode the filter mode to apply; must not be {@code null}
         * @return this builder
         */
        public Builder filterRuleForUrl(String urlPattern, FilterMode filterMode) {
            filterRules.add(new FilterRule(urlPattern, null, filterMode));
            return this;
        }

        /**
         * Adds a filter-mode override rule that applies to the given parameter name
         * across all URLs.
         *
         * @param parameterName exact parameter name; must not be {@code null}
         * @param filterMode    the filter mode to apply; must not be {@code null}
         * @return this builder
         */
        public Builder filterRuleForParam(String parameterName, FilterMode filterMode) {
            filterRules.add(new FilterRule(null, parameterName, filterMode));
            return this;
        }

        /**
         * Adds a filter-mode override rule for the given URL pattern and parameter name.
         *
         * @param urlPattern    Ant-style URL pattern; must not be {@code null}
         * @param parameterName exact parameter name; must not be {@code null}
         * @param filterMode    the filter mode to apply; must not be {@code null}
         * @return this builder
         */
        public Builder filterRule(String urlPattern, String parameterName, FilterMode filterMode) {
            filterRules.add(new FilterRule(urlPattern, parameterName, filterMode));
            return this;
        }

        /**
         * Adds an exclusion rule that skips XSS filtering for all parameters under
         * the given URL pattern.
         *
         * @param urlPattern Ant-style URL pattern; must not be {@code null}
         * @return this builder
         */
        public Builder excludeUrl(String urlPattern) {
            excludeRules.add(new ExcludeRule(urlPattern, null));
            return this;
        }

        /**
         * Adds an exclusion rule that skips XSS filtering for the given parameter name
         * across all URLs.
         *
         * @param parameterName exact parameter name; must not be {@code null}
         * @return this builder
         */
        public Builder excludeParam(String parameterName) {
            excludeRules.add(new ExcludeRule(null, parameterName));
            return this;
        }

        /**
         * Adds an exclusion rule that skips XSS filtering for the given URL pattern
         * and parameter name combination.
         *
         * @param urlPattern    Ant-style URL pattern; must not be {@code null}
         * @param parameterName exact parameter name; must not be {@code null}
         * @return this builder
         */
        public Builder excludeRule(String urlPattern, String parameterName) {
            excludeRules.add(new ExcludeRule(urlPattern, parameterName));
            return this;
        }

        /**
         * Adds characters to the blacklist escape set beyond the five defaults
         * ({@code &}, {@code <}, {@code >}, {@code "}, {@code '}).
         *
         * <p>Pre-defined entities are used for {@code /} and {@code `};
         * all other characters use numeric entities ({@code &#xHH;}).
         *
         * @param chars one or more characters to add
         * @return this builder
         */
        public Builder addEscapeChar(char... chars) {
            for (char c : chars) {
                addEscapeChars.add(c);
            }
            return this;
        }

        /**
         * Removes characters from the blacklist default escape set.
         *
         * <p>Removing core security characters ({@code &}, {@code <}, {@code >},
         * {@code "}, {@code '}) is permitted but strongly discouraged.
         *
         * @param chars one or more characters to remove
         * @return this builder
         */
        public Builder removeEscapeChar(char... chars) {
            for (char c : chars) {
                removeEscapeChars.add(c);
            }
            return this;
        }

        /**
         * Adds HTML tags to the whitelist default allowed tag set.
         * Tag names are normalized to lowercase.
         *
         * @param tags one or more tag names to add (e.g. {@code "video"}, {@code "audio"})
         * @return this builder
         */
        public Builder addAllowedTag(String... tags) {
            for (String tag : tags) {
                if (tag != null) {
                    addAllowedTags.add(tag.toLowerCase());
                }
            }
            return this;
        }

        /**
         * Removes HTML tags from the whitelist default allowed tag set.
         * Tag names are normalized to lowercase.
         *
         * @param tags one or more tag names to remove (e.g. {@code "strike"})
         * @return this builder
         */
        public Builder removeAllowedTag(String... tags) {
            for (String tag : tags) {
                if (tag != null) {
                    removeAllowedTags.add(tag.toLowerCase());
                }
            }
            return this;
        }

        /**
         * Adds CSS properties to the whitelist default allowed CSS property set.
         * Property names are normalized to lowercase.
         *
         * @param properties one or more CSS property names to add (e.g. {@code "line-height"})
         * @return this builder
         */
        public Builder addAllowedCssProperty(String... properties) {
            for (String property : properties) {
                if (property != null) {
                    addAllowedCssProperties.add(property.toLowerCase());
                }
            }
            return this;
        }

        /**
         * Removes CSS properties from the whitelist default allowed CSS property set.
         * Property names are normalized to lowercase.
         *
         * @param properties one or more CSS property names to remove (e.g. {@code "float"})
         * @return this builder
         */
        public Builder removeAllowedCssProperty(String... properties) {
            for (String property : properties) {
                if (property != null) {
                    removeAllowedCssProperties.add(property.toLowerCase());
                }
            }
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
