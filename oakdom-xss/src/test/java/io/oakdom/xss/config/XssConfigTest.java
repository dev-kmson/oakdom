package io.oakdom.xss.config;

import io.oakdom.core.filter.FilterMode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class XssConfigTest {

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    @Test
    void defaultGlobalFilterMode_isBlacklist() {
        assertThat(XssConfig.builder().build().getGlobalFilterMode())
                .isEqualTo(FilterMode.BLACKLIST);
    }

    @Test
    void defaultRules_areEmpty() {
        XssConfig config = XssConfig.builder().build();
        assertThat(config.getFilterRules()).isEmpty();
        assertThat(config.getExcludeRules()).isEmpty();
    }

    @Test
    void defaultCustomizations_areEmpty() {
        XssConfig config = XssConfig.builder().build();
        assertThat(config.getAddEscapeChars()).isEmpty();
        assertThat(config.getRemoveEscapeChars()).isEmpty();
        assertThat(config.getAddAllowedTags()).isEmpty();
        assertThat(config.getRemoveAllowedTags()).isEmpty();
        assertThat(config.getAddAllowedCssProperties()).isEmpty();
        assertThat(config.getRemoveAllowedCssProperties()).isEmpty();
    }

    // -------------------------------------------------------------------------
    // globalFilterMode
    // -------------------------------------------------------------------------

    @Test
    void globalFilterMode_setsCorrectly() {
        assertThat(XssConfig.builder().globalFilterMode(FilterMode.WHITELIST).build().getGlobalFilterMode())
                .isEqualTo(FilterMode.WHITELIST);
    }

    @Test
    void globalFilterMode_null_throwsException() {
        assertThatThrownBy(() -> XssConfig.builder().globalFilterMode(null).build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    // -------------------------------------------------------------------------
    // filterRuleForUrl
    // -------------------------------------------------------------------------

    @Test
    void filterRuleForUrl_createsRuleWithNullParam() {
        XssConfig config = XssConfig.builder()
                .filterRuleForUrl("/api/**", FilterMode.WHITELIST)
                .build();

        assertThat(config.getFilterRules()).hasSize(1);
        XssConfig.FilterRule rule = config.getFilterRules().get(0);
        assertThat(rule.getUrlPattern()).isEqualTo("/api/**");
        assertThat(rule.getParameterName()).isNull();
        assertThat(rule.getFilterMode()).isEqualTo(FilterMode.WHITELIST);
    }

    // -------------------------------------------------------------------------
    // filterRuleForParam
    // -------------------------------------------------------------------------

    @Test
    void filterRuleForParam_createsRuleWithNullUrl() {
        XssConfig config = XssConfig.builder()
                .filterRuleForParam("content", FilterMode.WHITELIST)
                .build();

        assertThat(config.getFilterRules()).hasSize(1);
        XssConfig.FilterRule rule = config.getFilterRules().get(0);
        assertThat(rule.getUrlPattern()).isNull();
        assertThat(rule.getParameterName()).isEqualTo("content");
        assertThat(rule.getFilterMode()).isEqualTo(FilterMode.WHITELIST);
    }

    // -------------------------------------------------------------------------
    // filterRule
    // -------------------------------------------------------------------------

    @Test
    void filterRule_createsBothUrlAndParam() {
        XssConfig config = XssConfig.builder()
                .filterRule("/api/editor/**", "content", FilterMode.WHITELIST)
                .build();

        XssConfig.FilterRule rule = config.getFilterRules().get(0);
        assertThat(rule.getUrlPattern()).isEqualTo("/api/editor/**");
        assertThat(rule.getParameterName()).isEqualTo("content");
        assertThat(rule.getFilterMode()).isEqualTo(FilterMode.WHITELIST);
    }

    // -------------------------------------------------------------------------
    // excludeUrl
    // -------------------------------------------------------------------------

    @Test
    void excludeUrl_createsRuleWithNullParam() {
        XssConfig config = XssConfig.builder().excludeUrl("/api/raw/**").build();

        XssConfig.ExcludeRule rule = config.getExcludeRules().get(0);
        assertThat(rule.getUrlPattern()).isEqualTo("/api/raw/**");
        assertThat(rule.getParameterName()).isNull();
    }

    // -------------------------------------------------------------------------
    // excludeParam
    // -------------------------------------------------------------------------

    @Test
    void excludeParam_createsRuleWithNullUrl() {
        XssConfig config = XssConfig.builder().excludeParam("token").build();

        XssConfig.ExcludeRule rule = config.getExcludeRules().get(0);
        assertThat(rule.getUrlPattern()).isNull();
        assertThat(rule.getParameterName()).isEqualTo("token");
    }

    // -------------------------------------------------------------------------
    // excludeRule
    // -------------------------------------------------------------------------

    @Test
    void excludeRule_createsBothUrlAndParam() {
        XssConfig config = XssConfig.builder()
                .excludeRule("/api/editor/**", "rawData")
                .build();

        XssConfig.ExcludeRule rule = config.getExcludeRules().get(0);
        assertThat(rule.getUrlPattern()).isEqualTo("/api/editor/**");
        assertThat(rule.getParameterName()).isEqualTo("rawData");
    }

    // -------------------------------------------------------------------------
    // Customization fields
    // -------------------------------------------------------------------------

    @Test
    void addEscapeChar_storesChars() {
        XssConfig config = XssConfig.builder().addEscapeChar('/', '`').build();
        assertThat(config.getAddEscapeChars()).containsExactly('/', '`');
    }

    @Test
    void removeEscapeChar_storesChars() {
        XssConfig config = XssConfig.builder().removeEscapeChar('\'').build();
        assertThat(config.getRemoveEscapeChars()).containsExactly('\'');
    }

    @Test
    void addAllowedTag_normalizesToLowercase() {
        XssConfig config = XssConfig.builder().addAllowedTag("Video", "AUDIO").build();
        assertThat(config.getAddAllowedTags()).containsExactlyInAnyOrder("video", "audio");
    }

    @Test
    void removeAllowedTag_normalizesToLowercase() {
        XssConfig config = XssConfig.builder().removeAllowedTag("Strike").build();
        assertThat(config.getRemoveAllowedTags()).containsExactly("strike");
    }

    @Test
    void addAllowedCssProperty_normalizesToLowercase() {
        XssConfig config = XssConfig.builder().addAllowedCssProperty("Line-Height").build();
        assertThat(config.getAddAllowedCssProperties()).containsExactly("line-height");
    }

    @Test
    void removeAllowedCssProperty_normalizesToLowercase() {
        XssConfig config = XssConfig.builder().removeAllowedCssProperty("Float").build();
        assertThat(config.getRemoveAllowedCssProperties()).containsExactly("float");
    }

    // -------------------------------------------------------------------------
    // Immutability
    // -------------------------------------------------------------------------

    @Test
    void filterRules_areImmutable() {
        XssConfig config = XssConfig.builder()
                .filterRuleForUrl("/api/**", FilterMode.WHITELIST)
                .build();

        assertThatThrownBy(() -> config.getFilterRules().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void excludeRules_areImmutable() {
        XssConfig config = XssConfig.builder().excludeUrl("/api/**").build();

        assertThatThrownBy(() -> config.getExcludeRules().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void customizationSets_areImmutable() {
        XssConfig config = XssConfig.builder()
                .addEscapeChar('/')
                .addAllowedTag("video")
                .addAllowedCssProperty("cursor")
                .build();

        assertThatThrownBy(() -> config.getAddEscapeChars().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> config.getAddAllowedTags().clear())
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> config.getAddAllowedCssProperties().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
