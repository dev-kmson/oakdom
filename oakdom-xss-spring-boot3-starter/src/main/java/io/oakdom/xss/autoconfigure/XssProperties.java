package io.oakdom.xss.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.Ordered;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for the oakdom XSS filter.
 *
 * <p>All properties are bound under the {@code oakdom.xss} prefix.
 *
 * <p>Example {@code application.properties}:
 * <pre>
 * oakdom.xss.enabled=true
 * oakdom.xss.global-filter-mode=BLACKLIST
 * oakdom.xss.exclude-urls=/api/upload/**,/api/raw/**
 * oakdom.xss.exclude-params=csrfToken,signature
 * oakdom.xss.filter-rules[0].url-pattern=/api/editor/**
 * oakdom.xss.filter-rules[0].param=content
 * oakdom.xss.filter-rules[0].mode=WHITELIST
 * oakdom.xss.exclude-rules[0].url-pattern=/api/editor/**
 * oakdom.xss.exclude-rules[0].param=rawData
 * </pre>
 */
@ConfigurationProperties(prefix = "oakdom.xss")
public class XssProperties {

    /**
     * Whether the XSS filter is enabled. Defaults to {@code true}.
     */
    private boolean enabled = true;

    /**
     * Global filter mode applied to all requests unless overridden by a filter rule.
     * Accepted values: {@code BLACKLIST} (default), {@code WHITELIST}.
     */
    private String globalFilterMode = "BLACKLIST";

    /**
     * URL patterns to exclude from XSS filtering entirely.
     * Supports Ant-style patterns ({@code ?}, {@code *}, {@code **}).
     */
    private List<String> excludeUrls = new ArrayList<String>();

    /**
     * Parameter names to exclude from XSS filtering on any URL.
     */
    private List<String> excludeParams = new ArrayList<String>();

    /**
     * Filter rules that override the global filter mode for specific URLs or parameters.
     *
     * <p>If both {@code urlPattern} and {@code param} are set, the rule applies to that
     * URL and parameter combination. If only {@code urlPattern} is set, the rule applies
     * to all parameters on that URL. If only {@code param} is set, the rule applies to
     * that parameter on any URL.
     */
    private List<FilterRuleProperty> filterRules = new ArrayList<FilterRuleProperty>();

    /**
     * Exclude rules that skip XSS filtering for a specific URL and parameter combination.
     *
     * <p>Both {@code urlPattern} and {@code param} must be set. For URL-only or
     * parameter-only exclusions, use {@code exclude-urls} or {@code exclude-params}.
     */
    private List<ExcludeRuleProperty> excludeRules = new ArrayList<ExcludeRuleProperty>();

    /**
     * Additional characters to add to the blacklist escape set.
     * Each entry must be a single character (e.g., {@code /}, {@code `}).
     */
    private List<String> addEscapeChars = new ArrayList<String>();

    /**
     * Characters to remove from the default blacklist escape set.
     * Removing default characters is permitted but strongly discouraged.
     */
    private List<String> removeEscapeChars = new ArrayList<String>();

    /**
     * Additional HTML tags to allow in WHITELIST mode (e.g., {@code iframe}, {@code embed}).
     */
    private List<String> addAllowedTags = new ArrayList<String>();

    /**
     * HTML tags to remove from the default WHITELIST allowed set.
     */
    private List<String> removeAllowedTags = new ArrayList<String>();

    /**
     * Additional CSS properties to allow in WHITELIST mode (e.g., {@code position}, {@code z-index}).
     */
    private List<String> addAllowedCssProperties = new ArrayList<String>();

    /**
     * CSS properties to remove from the default WHITELIST allowed set.
     */
    private List<String> removeAllowedCssProperties = new ArrayList<String>();

    /**
     * Order of the XSS filter in the filter chain.
     * Defaults to {@link Ordered#HIGHEST_PRECEDENCE} so the filter runs before all others.
     */
    private int filterOrder = Ordered.HIGHEST_PRECEDENCE;

    // -------------------------------------------------------------------------
    // Inner classes
    // -------------------------------------------------------------------------

    /**
     * A single filter rule entry that overrides the filter mode for a specific
     * URL pattern, parameter name, or URL+parameter combination.
     */
    public static class FilterRuleProperty {

        /**
         * Ant-style URL pattern this rule applies to. Optional — if omitted,
         * the rule applies to all URLs.
         */
        private String urlPattern;

        /**
         * Parameter name this rule applies to. Optional — if omitted,
         * the rule applies to all parameters.
         */
        private String param;

        /**
         * Filter mode for this rule: {@code BLACKLIST} or {@code WHITELIST}.
         * Defaults to {@code BLACKLIST}.
         */
        private String mode = "BLACKLIST";

        public String getUrlPattern() {
            return urlPattern;
        }

        public void setUrlPattern(String urlPattern) {
            this.urlPattern = urlPattern;
        }

        public String getParam() {
            return param;
        }

        public void setParam(String param) {
            this.param = param;
        }

        public String getMode() {
            return mode;
        }

        public void setMode(String mode) {
            this.mode = mode;
        }
    }

    /**
     * A single exclude rule entry that skips XSS filtering for a specific
     * URL pattern and parameter name combination.
     */
    public static class ExcludeRuleProperty {

        /**
         * Ant-style URL pattern this exclusion applies to.
         */
        private String urlPattern;

        /**
         * Parameter name this exclusion applies to.
         */
        private String param;

        public String getUrlPattern() {
            return urlPattern;
        }

        public void setUrlPattern(String urlPattern) {
            this.urlPattern = urlPattern;
        }

        public String getParam() {
            return param;
        }

        public void setParam(String param) {
            this.param = param;
        }
    }

    // -------------------------------------------------------------------------
    // Getters and setters
    // -------------------------------------------------------------------------

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getGlobalFilterMode() {
        return globalFilterMode;
    }

    public void setGlobalFilterMode(String globalFilterMode) {
        this.globalFilterMode = globalFilterMode;
    }

    public List<String> getExcludeUrls() {
        return excludeUrls;
    }

    public void setExcludeUrls(List<String> excludeUrls) {
        this.excludeUrls = excludeUrls;
    }

    public List<String> getExcludeParams() {
        return excludeParams;
    }

    public void setExcludeParams(List<String> excludeParams) {
        this.excludeParams = excludeParams;
    }

    public List<FilterRuleProperty> getFilterRules() {
        return filterRules;
    }

    public void setFilterRules(List<FilterRuleProperty> filterRules) {
        this.filterRules = filterRules;
    }

    public List<ExcludeRuleProperty> getExcludeRules() {
        return excludeRules;
    }

    public void setExcludeRules(List<ExcludeRuleProperty> excludeRules) {
        this.excludeRules = excludeRules;
    }

    public List<String> getAddEscapeChars() {
        return addEscapeChars;
    }

    public void setAddEscapeChars(List<String> addEscapeChars) {
        this.addEscapeChars = addEscapeChars;
    }

    public List<String> getRemoveEscapeChars() {
        return removeEscapeChars;
    }

    public void setRemoveEscapeChars(List<String> removeEscapeChars) {
        this.removeEscapeChars = removeEscapeChars;
    }

    public List<String> getAddAllowedTags() {
        return addAllowedTags;
    }

    public void setAddAllowedTags(List<String> addAllowedTags) {
        this.addAllowedTags = addAllowedTags;
    }

    public List<String> getRemoveAllowedTags() {
        return removeAllowedTags;
    }

    public void setRemoveAllowedTags(List<String> removeAllowedTags) {
        this.removeAllowedTags = removeAllowedTags;
    }

    public List<String> getAddAllowedCssProperties() {
        return addAllowedCssProperties;
    }

    public void setAddAllowedCssProperties(List<String> addAllowedCssProperties) {
        this.addAllowedCssProperties = addAllowedCssProperties;
    }

    public List<String> getRemoveAllowedCssProperties() {
        return removeAllowedCssProperties;
    }

    public void setRemoveAllowedCssProperties(List<String> removeAllowedCssProperties) {
        this.removeAllowedCssProperties = removeAllowedCssProperties;
    }

    public int getFilterOrder() {
        return filterOrder;
    }

    public void setFilterOrder(int filterOrder) {
        this.filterOrder = filterOrder;
    }
}
