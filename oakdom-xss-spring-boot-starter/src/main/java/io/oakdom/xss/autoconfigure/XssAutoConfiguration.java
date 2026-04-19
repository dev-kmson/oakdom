package io.oakdom.xss.autoconfigure;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.xss.config.XssConfig;
import io.oakdom.xss.filter.OakdomXssFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Auto-configuration for the oakdom XSS filter.
 *
 * <p>Activates automatically in Spring Boot 2.x web applications. Registers
 * {@link OakdomXssFilter} as a servlet filter that sanitizes all incoming HTTP
 * request parameters before they reach application code.
 *
 * <p>The filter is configured via {@link XssProperties} (prefix {@code oakdom.xss}).
 * For advanced rule-based configuration (URL/parameter-level overrides), define a
 * {@link XssConfig} bean in your application context — it will take precedence over
 * the properties-based configuration.
 *
 * <p>The filter can be disabled entirely with:
 * <pre>
 * oakdom.xss.enabled=false
 * </pre>
 */
@Configuration
@ConditionalOnWebApplication
@EnableConfigurationProperties(XssProperties.class)
@ConditionalOnProperty(prefix = "oakdom.xss", name = "enabled", havingValue = "true", matchIfMissing = true)
public class XssAutoConfiguration {

    /**
     * Creates a {@link XssConfig} from {@link XssProperties}.
     *
     * <p>If the application context already contains a {@link XssConfig} bean,
     * this method is skipped — the user-defined config takes precedence.
     *
     * @param properties the bound XSS properties
     * @return the XSS configuration
     */
    @Bean
    @ConditionalOnMissingBean
    public XssConfig xssConfig(XssProperties properties) {
        XssConfig.Builder builder = XssConfig.builder();

        if ("WHITELIST".equalsIgnoreCase(properties.getGlobalFilterMode())) {
            builder.globalFilterMode(FilterMode.WHITELIST);
        } else {
            builder.globalFilterMode(FilterMode.BLACKLIST);
        }

        for (String url : properties.getExcludeUrls()) {
            builder.excludeUrl(url);
        }
        for (String param : properties.getExcludeParams()) {
            builder.excludeParam(param);
        }

        for (XssProperties.FilterRuleProperty rule : properties.getFilterRules()) {
            FilterMode ruleMode = "WHITELIST".equalsIgnoreCase(rule.getMode())
                    ? FilterMode.WHITELIST : FilterMode.BLACKLIST;
            if (rule.getUrlPattern() != null && rule.getParam() != null) {
                builder.filterRule(rule.getUrlPattern(), rule.getParam(), ruleMode);
            } else if (rule.getUrlPattern() != null) {
                builder.filterRuleForUrl(rule.getUrlPattern(), ruleMode);
            } else if (rule.getParam() != null) {
                builder.filterRuleForParam(rule.getParam(), ruleMode);
            }
        }

        for (XssProperties.ExcludeRuleProperty rule : properties.getExcludeRules()) {
            if (rule.getUrlPattern() != null && rule.getParam() != null) {
                builder.excludeRule(rule.getUrlPattern(), rule.getParam());
            }
        }

        for (String ch : properties.getAddEscapeChars()) {
            if (ch != null && !ch.isEmpty()) {
                builder.addEscapeChar(ch.charAt(0));
            }
        }
        for (String ch : properties.getRemoveEscapeChars()) {
            if (ch != null && !ch.isEmpty()) {
                builder.removeEscapeChar(ch.charAt(0));
            }
        }

        if (!properties.getAddAllowedTags().isEmpty()) {
            builder.addAllowedTag(properties.getAddAllowedTags().toArray(new String[0]));
        }
        if (!properties.getRemoveAllowedTags().isEmpty()) {
            builder.removeAllowedTag(properties.getRemoveAllowedTags().toArray(new String[0]));
        }
        if (!properties.getAddAllowedCssProperties().isEmpty()) {
            builder.addAllowedCssProperty(properties.getAddAllowedCssProperties().toArray(new String[0]));
        }
        if (!properties.getRemoveAllowedCssProperties().isEmpty()) {
            builder.removeAllowedCssProperty(properties.getRemoveAllowedCssProperties().toArray(new String[0]));
        }

        return builder.build();
    }

    /**
     * Registers {@link OakdomXssFilter} in the servlet filter chain.
     *
     * <p>The filter is mapped to {@code /*} and ordered according to
     * {@code oakdom.xss.filter-order} (default: {@link org.springframework.core.Ordered#HIGHEST_PRECEDENCE}).
     *
     * @param xssConfig  the XSS configuration to apply
     * @param properties the bound XSS properties
     * @return the filter registration
     */
    @Bean
    @ConditionalOnMissingBean(name = "oakdomXssFilterRegistration")
    public FilterRegistrationBean oakdomXssFilterRegistration(XssConfig xssConfig, XssProperties properties) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(new OakdomXssFilter(xssConfig));
        registration.addUrlPatterns("/*");
        registration.setOrder(properties.getFilterOrder());
        registration.setName("oakdomXssFilter");
        return registration;
    }

    /**
     * Registers {@link OakdomXssMvcConfigurer} to add the annotation interceptor to
     * the Spring MVC interceptor chain.
     *
     * <p>If the application context already contains an {@link OakdomXssMvcConfigurer}
     * bean, this method is skipped.
     *
     * @return the MVC configurer that registers the annotation interceptor
     */
    @Bean
    @ConditionalOnMissingBean
    public OakdomXssMvcConfigurer oakdomXssMvcConfigurer() {
        return new OakdomXssMvcConfigurer();
    }
}
