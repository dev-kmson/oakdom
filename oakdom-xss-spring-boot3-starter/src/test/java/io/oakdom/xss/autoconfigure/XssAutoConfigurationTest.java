package io.oakdom.xss.autoconfigure;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.xss.config.XssConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import static org.assertj.core.api.Assertions.assertThat;

class XssAutoConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(XssAutoConfiguration.class));

    // -------------------------------------------------------------------------
    // Default configuration
    // -------------------------------------------------------------------------

    @Test
    void defaultConfig_registersFilter() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(XssConfig.class);
            assertThat(context).hasBean("oakdomXssFilterRegistration");
        });
    }

    @Test
    void defaultConfig_usesBlacklistMode() {
        contextRunner.run(context -> {
            XssConfig config = context.getBean(XssConfig.class);
            assertThat(config.getGlobalFilterMode()).isEqualTo(FilterMode.BLACKLIST);
        });
    }

    @Test
    void defaultConfig_filterOrderIsHighestPrecedence() {
        contextRunner.run(context -> {
            FilterRegistrationBean registration = context.getBean("oakdomXssFilterRegistration", FilterRegistrationBean.class);
            assertThat(registration.getOrder()).isEqualTo(Ordered.HIGHEST_PRECEDENCE);
        });
    }

    // -------------------------------------------------------------------------
    // Property binding
    // -------------------------------------------------------------------------

    @Test
    void property_globalFilterModeWhitelist_appliesWhitelistMode() {
        contextRunner
                .withPropertyValues("oakdom.xss.global-filter-mode=WHITELIST")
                .run(context -> {
                    XssConfig config = context.getBean(XssConfig.class);
                    assertThat(config.getGlobalFilterMode()).isEqualTo(FilterMode.WHITELIST);
                });
    }

    @Test
    void property_excludeUrls_appliedToConfig() {
        contextRunner
                .withPropertyValues("oakdom.xss.exclude-urls=/api/upload/**,/api/raw/**")
                .run(context -> {
                    XssConfig config = context.getBean(XssConfig.class);
                    assertThat(config.getExcludeRules()).hasSize(2);
                });
    }

    @Test
    void property_excludeParams_appliedToConfig() {
        contextRunner
                .withPropertyValues("oakdom.xss.exclude-params=csrfToken,signature")
                .run(context -> {
                    XssConfig config = context.getBean(XssConfig.class);
                    assertThat(config.getExcludeRules()).hasSize(2);
                });
    }

    @Test
    void property_filterOrder_appliedToRegistration() {
        contextRunner
                .withPropertyValues("oakdom.xss.filter-order=100")
                .run(context -> {
                    FilterRegistrationBean registration = context.getBean("oakdomXssFilterRegistration", FilterRegistrationBean.class);
                    assertThat(registration.getOrder()).isEqualTo(100);
                });
    }

    @Test
    void property_filterRuleUrlAndParam_appliedToConfig() {
        contextRunner
                .withPropertyValues(
                        "oakdom.xss.filter-rules[0].url-pattern=/api/editor/**",
                        "oakdom.xss.filter-rules[0].param=content",
                        "oakdom.xss.filter-rules[0].mode=WHITELIST")
                .run(context -> {
                    XssConfig config = context.getBean(XssConfig.class);
                    assertThat(config.getFilterRules()).hasSize(1);
                });
    }

    @Test
    void property_filterRuleUrlOnly_appliedToConfig() {
        contextRunner
                .withPropertyValues(
                        "oakdom.xss.filter-rules[0].url-pattern=/api/public/**",
                        "oakdom.xss.filter-rules[0].mode=WHITELIST")
                .run(context -> {
                    XssConfig config = context.getBean(XssConfig.class);
                    assertThat(config.getFilterRules()).hasSize(1);
                });
    }

    @Test
    void property_filterRuleParamOnly_appliedToConfig() {
        contextRunner
                .withPropertyValues(
                        "oakdom.xss.filter-rules[0].param=htmlBody",
                        "oakdom.xss.filter-rules[0].mode=WHITELIST")
                .run(context -> {
                    XssConfig config = context.getBean(XssConfig.class);
                    assertThat(config.getFilterRules()).hasSize(1);
                });
    }

    @Test
    void property_excludeRule_appliedToConfig() {
        contextRunner
                .withPropertyValues(
                        "oakdom.xss.exclude-rules[0].url-pattern=/api/editor/**",
                        "oakdom.xss.exclude-rules[0].param=rawData")
                .run(context -> {
                    XssConfig config = context.getBean(XssConfig.class);
                    assertThat(config.getExcludeRules()).hasSize(1);
                });
    }

    @Test
    void property_addEscapeChars_appliedToConfig() {
        contextRunner
                .withPropertyValues("oakdom.xss.add-escape-chars=/,`")
                .run(context -> {
                    assertThat(context).hasSingleBean(XssConfig.class);
                });
    }

    @Test
    void property_addAllowedTags_appliedToConfig() {
        contextRunner
                .withPropertyValues("oakdom.xss.add-allowed-tags=iframe,embed")
                .run(context -> {
                    assertThat(context).hasSingleBean(XssConfig.class);
                });
    }

    @Test
    void property_removeAllowedTags_appliedToConfig() {
        contextRunner
                .withPropertyValues("oakdom.xss.remove-allowed-tags=strike")
                .run(context -> {
                    assertThat(context).hasSingleBean(XssConfig.class);
                });
    }

    @Test
    void property_addAllowedCssProperties_appliedToConfig() {
        contextRunner
                .withPropertyValues("oakdom.xss.add-allowed-css-properties=position,z-index")
                .run(context -> {
                    assertThat(context).hasSingleBean(XssConfig.class);
                });
    }

    @Test
    void property_removeAllowedCssProperties_appliedToConfig() {
        contextRunner
                .withPropertyValues("oakdom.xss.remove-allowed-css-properties=float")
                .run(context -> {
                    assertThat(context).hasSingleBean(XssConfig.class);
                });
    }

    // -------------------------------------------------------------------------
    // Disabled
    // -------------------------------------------------------------------------

    @Test
    void property_enabledFalse_doesNotRegisterFilter() {
        contextRunner
                .withPropertyValues("oakdom.xss.enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(XssConfig.class);
                    assertThat(context).doesNotHaveBean("oakdomXssFilterRegistration");
                });
    }

    // -------------------------------------------------------------------------
    // Custom bean override
    // -------------------------------------------------------------------------

    @Test
    void customXssConfig_takesOverPropertiesConfig() {
        contextRunner
                .withUserConfiguration(CustomXssConfigConfiguration.class)
                .run(context -> {
                    XssConfig config = context.getBean(XssConfig.class);
                    assertThat(config.getGlobalFilterMode()).isEqualTo(FilterMode.WHITELIST);
                });
    }

    @Test
    void customFilterRegistration_replacesDefault() {
        contextRunner
                .withUserConfiguration(CustomFilterRegistrationConfiguration.class)
                .run(context -> {
                    FilterRegistrationBean registration = context.getBean("oakdomXssFilterRegistration", FilterRegistrationBean.class);
                    assertThat(registration.getOrder()).isEqualTo(999);
                });
    }

    // -------------------------------------------------------------------------
    // Helper configurations
    // -------------------------------------------------------------------------

    @Configuration
    static class CustomXssConfigConfiguration {
        @Bean
        public XssConfig xssConfig() {
            return XssConfig.builder()
                    .globalFilterMode(FilterMode.WHITELIST)
                    .build();
        }
    }

    @Configuration
    static class CustomFilterRegistrationConfiguration {
        @Bean
        public FilterRegistrationBean oakdomXssFilterRegistration(XssConfig xssConfig) {
            FilterRegistrationBean registration = new FilterRegistrationBean();
            registration.setFilter(new io.oakdom.xss.filter.OakdomXssFilter(xssConfig));
            registration.addUrlPatterns("/*");
            registration.setOrder(999);
            registration.setName("oakdomXssFilter");
            return registration;
        }
    }
}
