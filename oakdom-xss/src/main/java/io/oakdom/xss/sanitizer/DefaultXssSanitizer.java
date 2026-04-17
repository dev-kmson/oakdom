package io.oakdom.xss.sanitizer;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.xss.config.XssConfig;
import io.oakdom.xss.rule.BlacklistXssFilterRule;
import io.oakdom.xss.rule.WhitelistXssFilterRule;
import io.oakdom.xss.rule.XssFilterRule;

/**
 * Default implementation of {@link XssSanitizer} that delegates sanitization to an
 * {@link XssFilterRule} selected by the given {@link FilterMode}.
 *
 * <p>Use {@link #of(FilterMode)} to obtain a shared default instance:
 * <pre>{@code
 * String sanitized = DefaultXssSanitizer.of(FilterMode.BLACKLIST).sanitize(rawValue);
 * }</pre>
 *
 * <p>Use {@link #of(FilterMode, XssConfig)} to obtain an instance that reflects
 * the customizations defined in the given {@link XssConfig}:
 * <pre>{@code
 * DefaultXssSanitizer sanitizer = DefaultXssSanitizer.of(FilterMode.WHITELIST, config);
 * }</pre>
 *
 * <p>Two shared default instances are maintained internally — one per {@link FilterMode} — so
 * no allocation occurs on each call to {@link #of(FilterMode)}.
 *
 * @see BlacklistXssFilterRule
 * @see WhitelistXssFilterRule
 */
public class DefaultXssSanitizer implements XssSanitizer {

    private static final DefaultXssSanitizer BLACKLIST_INSTANCE =
            new DefaultXssSanitizer(new BlacklistXssFilterRule());

    private static final DefaultXssSanitizer WHITELIST_INSTANCE =
            new DefaultXssSanitizer(new WhitelistXssFilterRule());

    private final XssFilterRule rule;

    /**
     * Constructs a sanitizer backed by the given rule.
     *
     * @param rule the XSS filter rule to apply; must not be {@code null}
     */
    public DefaultXssSanitizer(XssFilterRule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("rule must not be null");
        }
        this.rule = rule;
    }

    /**
     * Returns a shared default {@link DefaultXssSanitizer} instance for the given {@link FilterMode}.
     *
     * @param filterMode the desired filter mode; must not be {@code null}
     * @return a pre-built sanitizer instance; never {@code null}
     */
    public static DefaultXssSanitizer of(FilterMode filterMode) {
        if (filterMode == null) {
            throw new IllegalArgumentException("filterMode must not be null");
        }
        return filterMode == FilterMode.WHITELIST ? WHITELIST_INSTANCE : BLACKLIST_INSTANCE;
    }

    /**
     * Creates a new {@link DefaultXssSanitizer} configured with the customizations
     * defined in the given {@link XssConfig}.
     *
     * <p>For {@link FilterMode#BLACKLIST}, the escape character set is adjusted according
     * to {@link XssConfig#getAddEscapeChars()} and {@link XssConfig#getRemoveEscapeChars()}.
     * For {@link FilterMode#WHITELIST}, the allowed tag set and allowed CSS property set are
     * adjusted according to the corresponding add/remove sets in {@link XssConfig}.
     *
     * <p>If {@code xssConfig} is {@code null}, this method delegates to {@link #of(FilterMode)}.
     *
     * @param filterMode the desired filter mode; must not be {@code null}
     * @param xssConfig  the configuration that may carry customizations; may be {@code null}
     * @return a sanitizer configured with the given customizations; never {@code null}
     */
    public static DefaultXssSanitizer of(FilterMode filterMode, XssConfig xssConfig) {
        if (filterMode == null) {
            throw new IllegalArgumentException("filterMode must not be null");
        }
        if (xssConfig == null) {
            return of(filterMode);
        }
        if (filterMode == FilterMode.WHITELIST) {
            return new DefaultXssSanitizer(new WhitelistXssFilterRule(
                    xssConfig.getAddAllowedTags(),
                    xssConfig.getRemoveAllowedTags(),
                    xssConfig.getAddAllowedCssProperties(),
                    xssConfig.getRemoveAllowedCssProperties()
            ));
        }
        return new DefaultXssSanitizer(new BlacklistXssFilterRule(
                xssConfig.getAddEscapeChars(),
                xssConfig.getRemoveEscapeChars()
        ));
    }

    /**
     * Sanitizes the given value by applying the configured {@link XssFilterRule}.
     *
     * @param value the raw input value; may be {@code null}
     * @return the sanitized value, or {@code null} if {@code value} is {@code null}
     */
    @Override
    public String sanitize(String value) {
        return rule.apply(value);
    }
}
