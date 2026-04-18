package io.oakdom.xss.filter;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.xss.config.XssConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OakdomXssFilterTest {

    private OakdomXssFilter filter;

    @BeforeEach
    void setUp() {
        filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .filterRule("/api/editor/**", "content", FilterMode.WHITELIST)
                .filterRuleForUrl("/api/public/**", FilterMode.WHITELIST)
                .filterRuleForParam("htmlBody", FilterMode.WHITELIST)
                .excludeUrl("/api/raw/**")
                .excludeParam("token")
                .excludeRule("/api/editor/**", "rawData")
                .build());
    }

    // -------------------------------------------------------------------------
    // resolveFilterMode — priority
    // -------------------------------------------------------------------------

    @Test
    void filterMode_urlAndParamRule_wins() {
        assertThat(filter.resolveFilterMode("/api/editor/post", "content"))
                .isEqualTo(FilterMode.WHITELIST);
    }

    @Test
    void filterMode_urlOnlyRule_appliesToAllParams() {
        assertThat(filter.resolveFilterMode("/api/public/page", "title"))
                .isEqualTo(FilterMode.WHITELIST);
    }

    @Test
    void filterMode_paramOnlyRule_appliesToAllUrls() {
        assertThat(filter.resolveFilterMode("/api/other", "htmlBody"))
                .isEqualTo(FilterMode.WHITELIST);
    }

    @Test
    void filterMode_noMatchingRule_returnsGlobal() {
        assertThat(filter.resolveFilterMode("/api/other", "title"))
                .isEqualTo(FilterMode.BLACKLIST);
    }

    @Test
    void filterMode_urlAndParamRuleWinsOverParamOnlyRule() {
        OakdomXssFilter priorityFilter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .filterRule("/api/editor/**", "content", FilterMode.WHITELIST)
                .filterRuleForParam("content", FilterMode.BLACKLIST)
                .build());

        assertThat(priorityFilter.resolveFilterMode("/api/editor/post", "content"))
                .isEqualTo(FilterMode.WHITELIST);
    }

    @Test
    void filterMode_paramOnlyRuleWinsOverUrlOnlyRule() {
        OakdomXssFilter priorityFilter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .filterRuleForUrl("/api/public/**", FilterMode.BLACKLIST)
                .filterRuleForParam("content", FilterMode.WHITELIST)
                .build());

        assertThat(priorityFilter.resolveFilterMode("/api/public/page", "content"))
                .isEqualTo(FilterMode.WHITELIST);
    }

    // -------------------------------------------------------------------------
    // shouldSkip
    // -------------------------------------------------------------------------

    @Test
    void shouldSkip_excludeUrl_matchesAnyParam() {
        assertThat(filter.shouldSkip("/api/raw/data", "anything")).isTrue();
    }

    @Test
    void shouldSkip_excludeParam_matchesAnyUrl() {
        assertThat(filter.shouldSkip("/api/other", "token")).isTrue();
    }

    @Test
    void shouldSkip_excludeRule_matchesUrlAndParam() {
        assertThat(filter.shouldSkip("/api/editor/post", "rawData")).isTrue();
    }

    @Test
    void shouldSkip_excludeRule_doesNotMatchWrongParam() {
        assertThat(filter.shouldSkip("/api/editor/post", "content")).isFalse();
    }

    @Test
    void shouldSkip_noMatchingRule_returnsFalse() {
        assertThat(filter.shouldSkip("/api/other", "title")).isFalse();
    }

    // -------------------------------------------------------------------------
    // sanitize
    // -------------------------------------------------------------------------

    @Test
    void sanitize_blacklistMode_escapesHtml() {
        assertThat(filter.sanitize("<script>", FilterMode.BLACKLIST))
                .isEqualTo("&lt;script&gt;");
    }

    @Test
    void sanitize_whitelistMode_allowsAllowedTags() {
        assertThat(filter.sanitize("<b>bold</b>", FilterMode.WHITELIST))
                .isEqualTo("<b>bold</b>");
    }

    @Test
    void sanitize_nullValue_returnsNull() {
        assertThat(filter.sanitize(null, FilterMode.BLACKLIST)).isNull();
        assertThat(filter.sanitize(null, FilterMode.WHITELIST)).isNull();
    }

    // -------------------------------------------------------------------------
    // Default constructor (configure override)
    // -------------------------------------------------------------------------

    @Test
    void defaultConstructor_usesBlacklistGlobalMode() {
        OakdomXssFilter defaultFilter = new OakdomXssFilter();
        assertThat(defaultFilter.resolveFilterMode("/any", "param"))
                .isEqualTo(FilterMode.BLACKLIST);
    }
}
