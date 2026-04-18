package io.oakdom.xss.rule;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class BlacklistXssFilterRuleTest {

    private final BlacklistXssFilterRule rule = new BlacklistXssFilterRule();

    // -------------------------------------------------------------------------
    // Null / empty
    // -------------------------------------------------------------------------

    @Test
    void nullInput_returnsNull() {
        assertThat(rule.apply(null)).isNull();
    }

    @Test
    void emptyString_returnsEmpty() {
        assertThat(rule.apply("")).isEmpty();
    }

    @Test
    void noSpecialChars_returnsUnchanged() {
        assertThat(rule.apply("Hello World")).isEqualTo("Hello World");
    }

    // -------------------------------------------------------------------------
    // Default escape set (5 core characters)
    // -------------------------------------------------------------------------

    @Test
    void ampersand_isEscaped() {
        assertThat(rule.apply("a & b")).isEqualTo("a &amp; b");
    }

    @Test
    void lessThan_isEscaped() {
        assertThat(rule.apply("<div>")).isEqualTo("&lt;div&gt;");
    }

    @Test
    void greaterThan_isEscaped() {
        assertThat(rule.apply("a > b")).isEqualTo("a &gt; b");
    }

    @Test
    void doubleQuote_isEscaped() {
        assertThat(rule.apply("say \"hello\"")).isEqualTo("say &quot;hello&quot;");
    }

    @Test
    void singleQuote_isEscaped() {
        assertThat(rule.apply("it's")).isEqualTo("it&#x27;s");
    }

    @Test
    void ampersandEscapedFirst_preventsDoubleEscaping() {
        // "&lt;" contains "&" which must be escaped to "&amp;" producing "&amp;lt;"
        assertThat(rule.apply("&lt;")).isEqualTo("&amp;lt;");
    }

    @Test
    void scriptTag_fullyEscaped() {
        assertThat(rule.apply("<script>alert('xss')</script>"))
                .isEqualTo("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;");
    }

    // -------------------------------------------------------------------------
    // Default does NOT escape / and `
    // -------------------------------------------------------------------------

    @Test
    void slash_notEscapedByDefault() {
        assertThat(rule.apply("a/b")).isEqualTo("a/b");
    }

    @Test
    void backtick_notEscapedByDefault() {
        assertThat(rule.apply("a`b")).isEqualTo("a`b");
    }

    // -------------------------------------------------------------------------
    // Custom: add escape characters
    // -------------------------------------------------------------------------

    @Test
    void addSlash_escapesSlash() {
        BlacklistXssFilterRule custom = ruleWithAdd('/');
        assertThat(custom.apply("a/b")).isEqualTo("a&#x2F;b");
    }

    @Test
    void addBacktick_escapesBacktick() {
        BlacklistXssFilterRule custom = ruleWithAdd('`');
        assertThat(custom.apply("a`b")).isEqualTo("a&#x60;b");
    }

    @Test
    void addUnknownChar_usesNumericEntity() {
        BlacklistXssFilterRule custom = ruleWithAdd('@');
        assertThat(custom.apply("user@example.com")).isEqualTo("user&#x40;example.com");
    }

    // -------------------------------------------------------------------------
    // Custom: remove escape characters
    // -------------------------------------------------------------------------

    @Test
    void removeSingleQuote_doesNotEscapeSingleQuote() {
        BlacklistXssFilterRule custom = ruleWithRemove('\'');
        assertThat(custom.apply("it's")).isEqualTo("it's");
    }

    @Test
    void removeQuote_stillEscapesOtherChars() {
        BlacklistXssFilterRule custom = ruleWithRemove('\'');
        assertThat(custom.apply("<b>it's</b>")).isEqualTo("&lt;b&gt;it's&lt;/b&gt;");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private BlacklistXssFilterRule ruleWithAdd(char... chars) {
        Set<Character> add = new LinkedHashSet<>();
        for (char c : chars) add.add(c);
        return new BlacklistXssFilterRule(add, Collections.emptySet());
    }

    private BlacklistXssFilterRule ruleWithRemove(char... chars) {
        Set<Character> remove = new LinkedHashSet<>();
        for (char c : chars) remove.add(c);
        return new BlacklistXssFilterRule(Collections.emptySet(), remove);
    }
}
