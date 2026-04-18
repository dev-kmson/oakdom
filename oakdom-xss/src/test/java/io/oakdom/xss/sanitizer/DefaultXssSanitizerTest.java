package io.oakdom.xss.sanitizer;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.xss.config.XssConfig;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultXssSanitizerTest {

    // -------------------------------------------------------------------------
    // of(FilterMode) — shared default instances
    // -------------------------------------------------------------------------

    @Test
    void of_blacklist_returnsSameInstance() {
        assertThat(DefaultXssSanitizer.of(FilterMode.BLACKLIST))
                .isSameAs(DefaultXssSanitizer.of(FilterMode.BLACKLIST));
    }

    @Test
    void of_whitelist_returnsSameInstance() {
        assertThat(DefaultXssSanitizer.of(FilterMode.WHITELIST))
                .isSameAs(DefaultXssSanitizer.of(FilterMode.WHITELIST));
    }

    @Test
    void of_nullFilterMode_throwsException() {
        assertThatThrownBy(() -> DefaultXssSanitizer.of(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void of_withConfig_nullFilterMode_throwsException() {
        assertThatThrownBy(() -> DefaultXssSanitizer.of(null, XssConfig.builder().build()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // -------------------------------------------------------------------------
    // Default blacklist behavior
    // -------------------------------------------------------------------------

    @Test
    void blacklist_escapesHtmlChars() {
        assertThat(DefaultXssSanitizer.of(FilterMode.BLACKLIST).sanitize("<script>alert('xss')</script>"))
                .isEqualTo("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;");
    }

    @Test
    void blacklist_doesNotEscapeSlash() {
        assertThat(DefaultXssSanitizer.of(FilterMode.BLACKLIST).sanitize("a/b")).isEqualTo("a/b");
    }

    // -------------------------------------------------------------------------
    // Default whitelist behavior
    // -------------------------------------------------------------------------

    @Test
    void whitelist_allowsAllowedTags() {
        assertThat(DefaultXssSanitizer.of(FilterMode.WHITELIST).sanitize("<b>bold</b>"))
                .isEqualTo("<b>bold</b>");
    }

    @Test
    void whitelist_escapesDisallowedTags() {
        assertThat(DefaultXssSanitizer.of(FilterMode.WHITELIST).sanitize("<script>alert(1)</script>"))
                .isEqualTo("&lt;script&gt;alert(1)&lt;&#x2F;script&gt;");
    }

    // -------------------------------------------------------------------------
    // of(FilterMode, XssConfig) — customized instances
    // -------------------------------------------------------------------------

    @Test
    void of_withNullConfig_returnsSameAsDefault() {
        assertThat(DefaultXssSanitizer.of(FilterMode.BLACKLIST, null))
                .isSameAs(DefaultXssSanitizer.of(FilterMode.BLACKLIST));
    }

    @Test
    void of_blacklistWithAddEscapeChar_escapesAddedChar() {
        XssConfig config = XssConfig.builder().addEscapeChar('/').build();
        String result = DefaultXssSanitizer.of(FilterMode.BLACKLIST, config).sanitize("a/b");
        assertThat(result).isEqualTo("a&#x2F;b");
    }

    @Test
    void of_blacklistWithRemoveEscapeChar_doesNotEscapeRemovedChar() {
        XssConfig config = XssConfig.builder().removeEscapeChar('\'').build();
        String result = DefaultXssSanitizer.of(FilterMode.BLACKLIST, config).sanitize("it's");
        assertThat(result).isEqualTo("it's");
    }

    @Test
    void of_whitelistWithAddAllowedTag_allowsNewTag() {
        XssConfig config = XssConfig.builder()
                .globalFilterMode(FilterMode.WHITELIST)
                .addAllowedTag("video")
                .build();
        String result = DefaultXssSanitizer.of(FilterMode.WHITELIST, config).sanitize("<video></video>");
        assertThat(result).isEqualTo("<video></video>");
    }

    @Test
    void of_whitelistWithRemoveAllowedTag_escapesRemovedTag() {
        XssConfig config = XssConfig.builder()
                .globalFilterMode(FilterMode.WHITELIST)
                .removeAllowedTag("strike")
                .build();
        String result = DefaultXssSanitizer.of(FilterMode.WHITELIST, config).sanitize("<strike>text</strike>");
        assertThat(result).isEqualTo("&lt;strike&gt;text&lt;&#x2F;strike&gt;");
    }

    @Test
    void of_whitelistWithAddCssProperty_allowsNewProperty() {
        XssConfig config = XssConfig.builder()
                .globalFilterMode(FilterMode.WHITELIST)
                .addAllowedCssProperty("cursor")
                .build();
        String result = DefaultXssSanitizer.of(FilterMode.WHITELIST, config)
                .sanitize("<span style=\"cursor: pointer;\">text</span>");
        assertThat(result).isEqualTo("<span style=\"cursor: pointer;\">text</span>");
    }

    @Test
    void of_whitelistWithRemoveAllowedCssProperty_removesProperty() {
        XssConfig config = XssConfig.builder()
                .globalFilterMode(FilterMode.WHITELIST)
                .removeAllowedCssProperty("float")
                .build();
        String result = DefaultXssSanitizer.of(FilterMode.WHITELIST, config)
                .sanitize("<div style=\"float: left;\">text</div>");
        assertThat(result).isEqualTo("<div>text</div>");
    }
}
