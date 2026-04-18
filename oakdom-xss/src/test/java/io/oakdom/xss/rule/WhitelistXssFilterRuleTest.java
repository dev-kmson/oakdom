package io.oakdom.xss.rule;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class WhitelistXssFilterRuleTest {

    private final WhitelistXssFilterRule rule = new WhitelistXssFilterRule();

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
    void plainText_returnsUnchanged() {
        assertThat(rule.apply("Hello World")).isEqualTo("Hello World");
    }

    @Test
    void plainTextWithSpecialChars_escapesHtml() {
        assertThat(rule.apply("1 < 2 & 3 > 0")).isEqualTo("1 &lt; 2 &amp; 3 &gt; 0");
    }

    // -------------------------------------------------------------------------
    // Allowed tags
    // -------------------------------------------------------------------------

    @Test
    void allowedTag_passesThrough() {
        assertThat(rule.apply("<b>bold</b>")).isEqualTo("<b>bold</b>");
    }

    @Test
    void allowedInlineTag_passesThrough() {
        assertThat(rule.apply("<em>text</em>")).isEqualTo("<em>text</em>");
    }

    @Test
    void allowedBlockTag_passesThrough() {
        assertThat(rule.apply("<p>paragraph</p>")).isEqualTo("<p>paragraph</p>");
    }

    @Test
    void html5SemanticTags_passThrough() {
        assertThat(rule.apply("<article><section><p>content</p></section></article>"))
                .isEqualTo("<article><section><p>content</p></section></article>");
    }

    @Test
    void html5LayoutTags_passThrough() {
        assertThat(rule.apply("<header>head</header><main>body</main><footer>foot</footer>"))
                .isEqualTo("<header>head</header><main>body</main><footer>foot</footer>");
    }

    @Test
    void hgroupTag_passesThrough() {
        assertThat(rule.apply("<hgroup><h1>Title</h1><p>Subtitle</p></hgroup>"))
                .isEqualTo("<hgroup><h1>Title</h1><p>Subtitle</p></hgroup>");
    }

    @Test
    void meterTag_withAttributes_isAllowed() {
        assertThat(rule.apply("<meter value=\"0.7\" min=\"0\" max=\"1\" low=\"0.3\" high=\"0.8\" optimum=\"1\">70%</meter>"))
                .isEqualTo("<meter value=\"0.7\" min=\"0\" max=\"1\" low=\"0.3\" high=\"0.8\" optimum=\"1\">70%</meter>");
    }

    @Test
    void progressTag_withAttributes_isAllowed() {
        assertThat(rule.apply("<progress value=\"50\" max=\"100\">50%</progress>"))
                .isEqualTo("<progress value=\"50\" max=\"100\">50%</progress>");
    }

    @Test
    void detailsSummary_passThrough() {
        assertThat(rule.apply("<details><summary>Show more</summary><p>Content</p></details>"))
                .isEqualTo("<details><summary>Show more</summary><p>Content</p></details>");
    }

    @Test
    void detailsOpen_isAllowed() {
        assertThat(rule.apply("<details open><summary>Title</summary><p>Content</p></details>"))
                .isEqualTo("<details open=\"\"><summary>Title</summary><p>Content</p></details>");
    }

    @Test
    void nestedAllowedTags_passThrough() {
        assertThat(rule.apply("<b><i>text</i></b>")).isEqualTo("<b><i>text</i></b>");
    }

    @Test
    void tableStructure_passesThrough() {
        String input = "<table><thead><tr><th>Name</th></tr></thead><tbody><tr><td>John</td></tr></tbody></table>";
        assertThat(rule.apply(input)).isEqualTo(input);
    }

    // -------------------------------------------------------------------------
    // Disallowed tags
    // -------------------------------------------------------------------------

    @Test
    void scriptTag_isEscaped() {
        assertThat(rule.apply("<script>alert(1)</script>"))
                .isEqualTo("&lt;script&gt;alert(1)&lt;&#x2F;script&gt;");
    }

    @Test
    void iframeTag_isEscaped() {
        assertThat(rule.apply("<iframe src='evil.com'></iframe>"))
                .isEqualTo("&lt;iframe src=&#x27;evil.com&#x27;&gt;&lt;&#x2F;iframe&gt;");
    }

    @Test
    void objectTag_isEscaped() {
        assertThat(rule.apply("<object data='evil'></object>"))
                .isEqualTo("&lt;object data=&#x27;evil&#x27;&gt;&lt;&#x2F;object&gt;");
    }

    // -------------------------------------------------------------------------
    // Event handler attributes
    // -------------------------------------------------------------------------

    @Test
    void onclickAttribute_isRemoved() {
        assertThat(rule.apply("<p onclick=\"alert(1)\">text</p>")).isEqualTo("<p>text</p>");
    }

    @Test
    void onclickBoolean_isRemoved() {
        // Boolean attribute without a value — ATTR_PATTERN optional value group still matches
        assertThat(rule.apply("<p onclick>text</p>")).isEqualTo("<p>text</p>");
    }

    @Test
    void onclickUpperCase_isRemoved() {
        assertThat(rule.apply("<p ONCLICK=\"alert(1)\">text</p>")).isEqualTo("<p>text</p>");
    }

    @Test
    void onclickMixedCase_isRemoved() {
        assertThat(rule.apply("<p OnClick=\"alert(1)\">text</p>")).isEqualTo("<p>text</p>");
    }

    @Test
    void onerrorAttribute_isRemoved() {
        assertThat(rule.apply("<img src=\"x\" onerror=\"alert(1)\">")).isEqualTo("<img src=\"x\">");
    }

    @Test
    void onloadAttribute_isRemoved() {
        assertThat(rule.apply("<img src=\"safe.png\" onload=\"alert(1)\">")).isEqualTo("<img src=\"safe.png\">");
    }

    @Test
    void onmouseoverAttribute_isRemoved() {
        assertThat(rule.apply("<a href=\"/\" onmouseover=\"alert(1)\">link</a>"))
                .isEqualTo("<a href=\"/\">link</a>");
    }

    // -------------------------------------------------------------------------
    // href / src URL validation
    // -------------------------------------------------------------------------

    @Test
    void href_withHttpsUrl_isAllowed() {
        assertThat(rule.apply("<a href=\"https://example.com\">link</a>"))
                .isEqualTo("<a href=\"https://example.com\">link</a>");
    }

    @Test
    void href_withHttpUrl_isAllowed() {
        assertThat(rule.apply("<a href=\"http://example.com\">link</a>"))
                .isEqualTo("<a href=\"http://example.com\">link</a>");
    }

    @Test
    void href_withProtocolRelativeUrl_isAllowed() {
        assertThat(rule.apply("<a href=\"//example.com/path\">link</a>"))
                .isEqualTo("<a href=\"//example.com/path\">link</a>");
    }

    @Test
    void href_withRelativePath_isAllowed() {
        assertThat(rule.apply("<a href=\"/page\">link</a>"))
                .isEqualTo("<a href=\"/page\">link</a>");
    }

    @Test
    void href_withFragment_isAllowed() {
        assertThat(rule.apply("<a href=\"#section\">link</a>"))
                .isEqualTo("<a href=\"#section\">link</a>");
    }

    @Test
    void href_withJavascriptScheme_isRemoved() {
        assertThat(rule.apply("<a href=\"javascript:alert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withEncodedColonJavascriptScheme_isRemoved() {
        // "javascript&#58;" is decoded by browsers to "javascript:" — must be rejected
        assertThat(rule.apply("<a href=\"javascript&#58;alert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withPercentEncodedColonJavascriptScheme_isRemoved() {
        // "javascript%3aalert(1)" — percent-encoded colon bypass attempt
        assertThat(rule.apply("<a href=\"javascript%3aalert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withJavascriptScheme_upperCase_isRemoved() {
        // "JAVASCRIPT:" — isSafeUrl() lowercases before checking
        assertThat(rule.apply("<a href=\"JAVASCRIPT:alert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withJavascriptScheme_leadingWhitespace_isRemoved() {
        // " javascript:" — isSafeUrl() trims before checking
        assertThat(rule.apply("<a href=\" javascript:alert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withTelScheme_isAllowed() {
        assertThat(rule.apply("<a href=\"tel:+821012345678\">Call</a>"))
                .isEqualTo("<a href=\"tel:+821012345678\">Call</a>");
    }

    @Test
    void href_withMailtoScheme_isAllowed() {
        assertThat(rule.apply("<a href=\"mailto:user@example.com\">Email</a>"))
                .isEqualTo("<a href=\"mailto:user@example.com\">Email</a>");
    }

    @Test
    void href_withVbscriptScheme_isRemoved() {
        assertThat(rule.apply("<a href=\"vbscript:MsgBox(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withDataScheme_isRemoved() {
        assertThat(rule.apply("<a href=\"data:text/html,<script>alert(1)</script>\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withHexEntityEncodedColon_isRemoved() {
        // "javascript&#x3a;" — hex entity form of ':', normalized by isSafeUrl() before check
        assertThat(rule.apply("<a href=\"javascript&#x3a;alert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withDecimalEntityLeadingZero_isRemoved() {
        // "&#0058;" is the same colon as "&#58;" per HTML5 — leading zeros are valid
        assertThat(rule.apply("<a href=\"javascript&#0058;alert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withDecimalEntityMultipleLeadingZeros_isRemoved() {
        // "&#00058;" — multiple leading zeros, still valid HTML5 decimal entity for ':'
        assertThat(rule.apply("<a href=\"javascript&#00058;alert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withHexEntityLeadingZeros_isRemoved() {
        // "&#x003a;" — hex entity with leading zeros, equivalent to "&#x3a;"
        assertThat(rule.apply("<a href=\"javascript&#x003a;alert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withNamedColonEntity_isRemoved() {
        // "&colon;" is the HTML5 named entity for ':' — must be normalized before scheme check
        assertThat(rule.apply("<a href=\"javascript&colon;alert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withEntityMissingSemicolon_isSafeOutput() {
        // "&#x3a" without terminating ';' is not a valid HTML entity — isSafeUrl() does not
        // normalize it (no literal ':' present), so the href is passed through with '&' escaped
        // to '&amp;'. Modern browsers do not decode unterminated entities in attribute values,
        // so the resulting href "javascript&amp;#x3aalert(1)" is not executed as a script URL.
        assertThat(rule.apply("<a href=\"javascript&#x3aalert(1)\">link</a>"))
                .isEqualTo("<a href=\"javascript&amp;#x3aalert(1)\">link</a>");
    }

    @Test
    void href_withUppercasePercentEncodedColon_isRemoved() {
        // "javascript%3A" — uppercase percent-encoded colon, toLowerCase() + %3a replace normalizes it
        assertThat(rule.apply("<a href=\"javascript%3Aalert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_unquotedJavascriptScheme_isRemoved() {
        // Unquoted href — ATTR_PATTERN group 4 captures unquoted value, isSafeUrl() blocks it
        assertThat(rule.apply("<a href=javascript:alert(1)>link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withHtmlEntityEncodedFirstChar_isRemoved() {
        // Browser decodes &#106; to 'j', making "javascript:alert(1)".
        // isSafeUrl() does not decode this entity, but the colon in alert(1) is still detected.
        assertThat(rule.apply("<a href=\"&#106;avascript:alert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withTabInScheme_isRemoved() {
        // Tab inside "javascript" does not bypass isSafeUrl() — colon is still detected.
        assertThat(rule.apply("<a href=\"java\tscript:alert(1)\">link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void href_withBacktickDelimiter_isRemoved() {
        // Backtick is not a recognized attribute delimiter; value is captured as unquoted.
        // isSafeUrl() detects the colon and rejects it.
        assertThat(rule.apply("<a href=`javascript:alert(1)`>link</a>"))
                .isEqualTo("<a>link</a>");
    }

    @Test
    void imgSrc_withHttpsUrl_isAllowed() {
        assertThat(rule.apply("<img src=\"https://example.com/img.png\" alt=\"image\">"))
                .isEqualTo("<img src=\"https://example.com/img.png\" alt=\"image\">");
    }

    @Test
    void imgSrc_withJavascriptScheme_isRemoved() {
        assertThat(rule.apply("<img src=\"javascript:alert(1)\">"))
                .isEqualTo("<img>");
    }

    // -------------------------------------------------------------------------
    // Single-quoted attribute values
    // -------------------------------------------------------------------------

    @Test
    void singleQuotedAttr_isNormalizedToDoubleQuotes() {
        assertThat(rule.apply("<a href='/page'>link</a>"))
                .isEqualTo("<a href=\"/page\">link</a>");
    }

    // -------------------------------------------------------------------------
    // style attribute — CSS sanitization
    // -------------------------------------------------------------------------

    @Test
    void style_withSafeProperty_isAllowed() {
        assertThat(rule.apply("<span style=\"color: red;\">text</span>"))
                .isEqualTo("<span style=\"color: red;\">text</span>");
    }

    @Test
    void style_withDangerousExpression_isRemoved() {
        assertThat(rule.apply("<span style=\"expression(alert(1))\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withJavascriptInValue_isRemoved() {
        assertThat(rule.apply("<span style=\"color: javascript:red\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withDisallowedProperty_isRemoved() {
        assertThat(rule.apply("<span style=\"position: fixed;\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withSafeUrlInBackgroundImage_isAllowed() {
        assertThat(rule.apply("<div style=\"background-image: url(https://example.com/bg.jpg);\">text</div>"))
                .isEqualTo("<div style=\"background-image: url(https://example.com/bg.jpg);\">text</div>");
    }

    @Test
    void style_withDangerousUrlInBackgroundImage_isRemoved() {
        assertThat(rule.apply("<div style=\"background-image: url(javascript:alert(1));\">text</div>"))
                .isEqualTo("<div>text</div>");
    }

    @Test
    void style_withBehaviorProperty_isRemoved() {
        assertThat(rule.apply("<span style=\"behavior: url(evil.htc);\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withMozBinding_isRemoved() {
        assertThat(rule.apply("<span style=\"-moz-binding: url(evil.xml#xss);\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withVbscriptInValue_isRemoved() {
        // DANGEROUS_CSS_VALUE pattern includes vbscript: — must be blocked even in an allowed property
        assertThat(rule.apply("<span style=\"color: vbscript:red;\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withAtImportAsProperty_isRemoved() {
        // @import does not match CSS property:value pattern — silently dropped
        assertThat(rule.apply("<span style=\"@import url(evil.css);\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withAtImportInValue_isRemoved() {
        // @import in a property value — caught by DANGEROUS_CSS_VALUE
        assertThat(rule.apply("<span style=\"color: @import url(evil.css);\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withListStyleType_isAllowed() {
        assertThat(rule.apply("<ul style=\"list-style-type: disc;\"><li>item</li></ul>"))
                .isEqualTo("<ul style=\"list-style-type: disc;\"><li>item</li></ul>");
    }

    @Test
    void style_withListStylePosition_isAllowed() {
        assertThat(rule.apply("<ol style=\"list-style-position: inside;\"><li>item</li></ol>"))
                .isEqualTo("<ol style=\"list-style-position: inside;\"><li>item</li></ol>");
    }

    @Test
    void style_withListStyle_shorthand_isAllowed() {
        assertThat(rule.apply("<ul style=\"list-style: square inside;\"><li>item</li></ul>"))
                .isEqualTo("<ul style=\"list-style: square inside;\"><li>item</li></ul>");
    }

    // border side longhands
    @Test
    void style_withBorderTopColor_isAllowed() {
        assertThat(rule.apply("<div style=\"border-top-color: red;\">text</div>"))
                .isEqualTo("<div style=\"border-top-color: red;\">text</div>");
    }

    @Test
    void style_withBorderRightColor_isAllowed() {
        assertThat(rule.apply("<div style=\"border-right-color: blue;\">text</div>"))
                .isEqualTo("<div style=\"border-right-color: blue;\">text</div>");
    }

    @Test
    void style_withBorderBottomColor_isAllowed() {
        assertThat(rule.apply("<div style=\"border-bottom-color: green;\">text</div>"))
                .isEqualTo("<div style=\"border-bottom-color: green;\">text</div>");
    }

    @Test
    void style_withBorderLeftColor_isAllowed() {
        assertThat(rule.apply("<div style=\"border-left-color: gray;\">text</div>"))
                .isEqualTo("<div style=\"border-left-color: gray;\">text</div>");
    }

    @Test
    void style_withBorderTopWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"border-top-width: 2px;\">text</div>"))
                .isEqualTo("<div style=\"border-top-width: 2px;\">text</div>");
    }

    @Test
    void style_withBorderRightWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"border-right-width: 2px;\">text</div>"))
                .isEqualTo("<div style=\"border-right-width: 2px;\">text</div>");
    }

    @Test
    void style_withBorderBottomWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"border-bottom-width: 2px;\">text</div>"))
                .isEqualTo("<div style=\"border-bottom-width: 2px;\">text</div>");
    }

    @Test
    void style_withBorderLeftWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"border-left-width: 2px;\">text</div>"))
                .isEqualTo("<div style=\"border-left-width: 2px;\">text</div>");
    }

    @Test
    void style_withBorderTopStyle_isAllowed() {
        assertThat(rule.apply("<div style=\"border-top-style: dashed;\">text</div>"))
                .isEqualTo("<div style=\"border-top-style: dashed;\">text</div>");
    }

    @Test
    void style_withBorderRightStyle_isAllowed() {
        assertThat(rule.apply("<div style=\"border-right-style: dotted;\">text</div>"))
                .isEqualTo("<div style=\"border-right-style: dotted;\">text</div>");
    }

    @Test
    void style_withBorderBottomStyle_isAllowed() {
        assertThat(rule.apply("<div style=\"border-bottom-style: solid;\">text</div>"))
                .isEqualTo("<div style=\"border-bottom-style: solid;\">text</div>");
    }

    @Test
    void style_withBorderLeftStyle_isAllowed() {
        assertThat(rule.apply("<div style=\"border-left-style: none;\">text</div>"))
                .isEqualTo("<div style=\"border-left-style: none;\">text</div>");
    }

    @Test
    void style_withBorderTopLeftRadius_isAllowed() {
        assertThat(rule.apply("<div style=\"border-top-left-radius: 8px;\">text</div>"))
                .isEqualTo("<div style=\"border-top-left-radius: 8px;\">text</div>");
    }

    @Test
    void style_withBorderTopRightRadius_isAllowed() {
        assertThat(rule.apply("<div style=\"border-top-right-radius: 8px;\">text</div>"))
                .isEqualTo("<div style=\"border-top-right-radius: 8px;\">text</div>");
    }

    @Test
    void style_withBorderBottomRightRadius_isAllowed() {
        assertThat(rule.apply("<div style=\"border-bottom-right-radius: 8px;\">text</div>"))
                .isEqualTo("<div style=\"border-bottom-right-radius: 8px;\">text</div>");
    }

    @Test
    void style_withBorderBottomLeftRadius_isAllowed() {
        assertThat(rule.apply("<div style=\"border-bottom-left-radius: 8px;\">text</div>"))
                .isEqualTo("<div style=\"border-bottom-left-radius: 8px;\">text</div>");
    }

    // logical border longhands
    @Test
    void style_withBorderInlineColor_isAllowed() {
        assertThat(rule.apply("<div style=\"border-inline-color: red;\">text</div>"))
                .isEqualTo("<div style=\"border-inline-color: red;\">text</div>");
    }

    @Test
    void style_withBorderInlineStartColor_isAllowed() {
        assertThat(rule.apply("<div style=\"border-inline-start-color: blue;\">text</div>"))
                .isEqualTo("<div style=\"border-inline-start-color: blue;\">text</div>");
    }

    @Test
    void style_withBorderInlineEndColor_isAllowed() {
        assertThat(rule.apply("<div style=\"border-inline-end-color: green;\">text</div>"))
                .isEqualTo("<div style=\"border-inline-end-color: green;\">text</div>");
    }

    @Test
    void style_withBorderInlineWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"border-inline-width: 2px;\">text</div>"))
                .isEqualTo("<div style=\"border-inline-width: 2px;\">text</div>");
    }

    @Test
    void style_withBorderInlineStartWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"border-inline-start-width: 2px;\">text</div>"))
                .isEqualTo("<div style=\"border-inline-start-width: 2px;\">text</div>");
    }

    @Test
    void style_withBorderInlineEndWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"border-inline-end-width: 2px;\">text</div>"))
                .isEqualTo("<div style=\"border-inline-end-width: 2px;\">text</div>");
    }

    @Test
    void style_withBorderInlineStyle_isAllowed() {
        assertThat(rule.apply("<div style=\"border-inline-style: dashed;\">text</div>"))
                .isEqualTo("<div style=\"border-inline-style: dashed;\">text</div>");
    }

    @Test
    void style_withBorderInlineStartStyle_isAllowed() {
        assertThat(rule.apply("<div style=\"border-inline-start-style: solid;\">text</div>"))
                .isEqualTo("<div style=\"border-inline-start-style: solid;\">text</div>");
    }

    @Test
    void style_withBorderInlineEndStyle_isAllowed() {
        assertThat(rule.apply("<div style=\"border-inline-end-style: dotted;\">text</div>"))
                .isEqualTo("<div style=\"border-inline-end-style: dotted;\">text</div>");
    }

    @Test
    void style_withBorderBlockColor_isAllowed() {
        assertThat(rule.apply("<div style=\"border-block-color: red;\">text</div>"))
                .isEqualTo("<div style=\"border-block-color: red;\">text</div>");
    }

    @Test
    void style_withBorderBlockStartColor_isAllowed() {
        assertThat(rule.apply("<div style=\"border-block-start-color: blue;\">text</div>"))
                .isEqualTo("<div style=\"border-block-start-color: blue;\">text</div>");
    }

    @Test
    void style_withBorderBlockEndColor_isAllowed() {
        assertThat(rule.apply("<div style=\"border-block-end-color: gray;\">text</div>"))
                .isEqualTo("<div style=\"border-block-end-color: gray;\">text</div>");
    }

    @Test
    void style_withBorderBlockWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"border-block-width: 1px;\">text</div>"))
                .isEqualTo("<div style=\"border-block-width: 1px;\">text</div>");
    }

    @Test
    void style_withBorderBlockStartWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"border-block-start-width: 1px;\">text</div>"))
                .isEqualTo("<div style=\"border-block-start-width: 1px;\">text</div>");
    }

    @Test
    void style_withBorderBlockEndWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"border-block-end-width: 1px;\">text</div>"))
                .isEqualTo("<div style=\"border-block-end-width: 1px;\">text</div>");
    }

    @Test
    void style_withBorderBlockStyle_isAllowed() {
        assertThat(rule.apply("<div style=\"border-block-style: solid;\">text</div>"))
                .isEqualTo("<div style=\"border-block-style: solid;\">text</div>");
    }

    @Test
    void style_withBorderBlockStartStyle_isAllowed() {
        assertThat(rule.apply("<div style=\"border-block-start-style: dashed;\">text</div>"))
                .isEqualTo("<div style=\"border-block-start-style: dashed;\">text</div>");
    }

    @Test
    void style_withBorderBlockEndStyle_isAllowed() {
        assertThat(rule.apply("<div style=\"border-block-end-style: none;\">text</div>"))
                .isEqualTo("<div style=\"border-block-end-style: none;\">text</div>");
    }

    @Test
    void style_withBorderCollapse_isAllowed() {
        assertThat(rule.apply("<table style=\"border-collapse: collapse;\"><tr><td>cell</td></tr></table>"))
                .isEqualTo("<table style=\"border-collapse: collapse;\"><tr><td>cell</td></tr></table>");
    }

    @Test
    void style_withBorderSpacing_isAllowed() {
        assertThat(rule.apply("<table style=\"border-spacing: 4px;\"><tr><td>cell</td></tr></table>"))
                .isEqualTo("<table style=\"border-spacing: 4px;\"><tr><td>cell</td></tr></table>");
    }

    @Test
    void style_withWordBreak_isAllowed() {
        // word-break: break-all is commonly needed for Korean/CJK text
        assertThat(rule.apply("<p style=\"word-break: break-all;\">text</p>"))
                .isEqualTo("<p style=\"word-break: break-all;\">text</p>");
    }

    @Test
    void style_withOverflowWrap_isAllowed() {
        assertThat(rule.apply("<div style=\"overflow-wrap: break-word;\">text</div>"))
                .isEqualTo("<div style=\"overflow-wrap: break-word;\">text</div>");
    }

    @Test
    void style_withOverflow_isAllowed() {
        assertThat(rule.apply("<div style=\"overflow: hidden;\">text</div>"))
                .isEqualTo("<div style=\"overflow: hidden;\">text</div>");
    }

    @Test
    void style_withOverflowInline_isAllowed() {
        assertThat(rule.apply("<div style=\"overflow-inline: auto;\">text</div>"))
                .isEqualTo("<div style=\"overflow-inline: auto;\">text</div>");
    }

    @Test
    void style_withOverflowBlock_isAllowed() {
        assertThat(rule.apply("<div style=\"overflow-block: scroll;\">text</div>"))
                .isEqualTo("<div style=\"overflow-block: scroll;\">text</div>");
    }

    @Test
    void style_withOverflowAnchor_isAllowed() {
        assertThat(rule.apply("<div style=\"overflow-anchor: none;\">text</div>"))
                .isEqualTo("<div style=\"overflow-anchor: none;\">text</div>");
    }

    @Test
    void style_withTextOverflow_isAllowed() {
        assertThat(rule.apply("<div style=\"overflow: hidden; text-overflow: ellipsis; white-space: nowrap;\">long text</div>"))
                .isEqualTo("<div style=\"overflow: hidden; text-overflow: ellipsis; white-space: nowrap;\">long text</div>");
    }

    @Test
    void style_withBoxSizing_isAllowed() {
        assertThat(rule.apply("<div style=\"box-sizing: border-box;\">text</div>"))
                .isEqualTo("<div style=\"box-sizing: border-box;\">text</div>");
    }

    @Test
    void style_withTableLayout_isAllowed() {
        assertThat(rule.apply("<table style=\"table-layout: fixed;\"><tr><td>cell</td></tr></table>"))
                .isEqualTo("<table style=\"table-layout: fixed;\"><tr><td>cell</td></tr></table>");
    }

    @Test
    void style_withBackgroundPosition_isAllowed() {
        assertThat(rule.apply("<div style=\"background-position: center;\">text</div>"))
                .isEqualTo("<div style=\"background-position: center;\">text</div>");
    }

    @Test
    void style_withBackgroundSize_isAllowed() {
        assertThat(rule.apply("<div style=\"background-size: cover;\">text</div>"))
                .isEqualTo("<div style=\"background-size: cover;\">text</div>");
    }

    @Test
    void style_withBackgroundRepeat_isAllowed() {
        assertThat(rule.apply("<div style=\"background-repeat: no-repeat;\">text</div>"))
                .isEqualTo("<div style=\"background-repeat: no-repeat;\">text</div>");
    }

    @Test
    void style_withTextShadow_isAllowed() {
        assertThat(rule.apply("<p style=\"text-shadow: 1px 1px 2px black;\">text</p>"))
                .isEqualTo("<p style=\"text-shadow: 1px 1px 2px black;\">text</p>");
    }

    @Test
    void style_withBoxShadow_isAllowed() {
        assertThat(rule.apply("<div style=\"box-shadow: 0 2px 4px rgba(0,0,0,0.3);\">text</div>"))
                .isEqualTo("<div style=\"box-shadow: 0 2px 4px rgba(0,0,0,0.3);\">text</div>");
    }

    @Test
    void style_withFlexbox_isAllowed() {
        assertThat(rule.apply("<div style=\"display: flex; justify-content: center; align-items: center;\">text</div>"))
                .isEqualTo("<div style=\"display: flex; justify-content: center; align-items: center;\">text</div>");
    }

    @Test
    void style_withFlexDirection_isAllowed() {
        assertThat(rule.apply("<div style=\"flex-direction: column;\">text</div>"))
                .isEqualTo("<div style=\"flex-direction: column;\">text</div>");
    }

    @Test
    void style_withGap_isAllowed() {
        assertThat(rule.apply("<div style=\"display: flex; gap: 16px;\">text</div>"))
                .isEqualTo("<div style=\"display: flex; gap: 16px;\">text</div>");
    }

    @Test
    void style_withDirection_isAllowed() {
        assertThat(rule.apply("<p style=\"direction: rtl;\">RTL text</p>"))
                .isEqualTo("<p style=\"direction: rtl;\">RTL text</p>");
    }

    @Test
    void style_withInlineSize_isAllowed() {
        assertThat(rule.apply("<div style=\"inline-size: 100%;\">text</div>"))
                .isEqualTo("<div style=\"inline-size: 100%;\">text</div>");
    }

    @Test
    void style_withBlockSize_isAllowed() {
        assertThat(rule.apply("<div style=\"block-size: 200px;\">text</div>"))
                .isEqualTo("<div style=\"block-size: 200px;\">text</div>");
    }

    @Test
    void style_withMinInlineSize_isAllowed() {
        assertThat(rule.apply("<div style=\"min-inline-size: 300px;\">text</div>"))
                .isEqualTo("<div style=\"min-inline-size: 300px;\">text</div>");
    }

    @Test
    void style_withMaxBlockSize_isAllowed() {
        assertThat(rule.apply("<div style=\"max-block-size: 400px;\">text</div>"))
                .isEqualTo("<div style=\"max-block-size: 400px;\">text</div>");
    }

    @Test
    void style_withBorderStartStartRadius_isAllowed() {
        assertThat(rule.apply("<div style=\"border-start-start-radius: 8px;\">text</div>"))
                .isEqualTo("<div style=\"border-start-start-radius: 8px;\">text</div>");
    }

    @Test
    void style_withBorderEndEndRadius_isAllowed() {
        assertThat(rule.apply("<div style=\"border-end-end-radius: 8px;\">text</div>"))
                .isEqualTo("<div style=\"border-end-end-radius: 8px;\">text</div>");
    }

    @Test
    void style_withViewTransitionName_isAllowed() {
        assertThat(rule.apply("<div style=\"view-transition-name: hero;\">text</div>"))
                .isEqualTo("<div style=\"view-transition-name: hero;\">text</div>");
    }

    @Test
    void style_withMarginInline_isAllowed() {
        assertThat(rule.apply("<p style=\"margin-inline: auto;\">text</p>"))
                .isEqualTo("<p style=\"margin-inline: auto;\">text</p>");
    }

    @Test
    void style_withPaddingBlock_isAllowed() {
        assertThat(rule.apply("<div style=\"padding-block: 1rem;\">text</div>"))
                .isEqualTo("<div style=\"padding-block: 1rem;\">text</div>");
    }

    @Test
    void style_withColumnCount_isAllowed() {
        assertThat(rule.apply("<div style=\"column-count: 2; column-gap: 1rem;\">text</div>"))
                .isEqualTo("<div style=\"column-count: 2; column-gap: 1rem;\">text</div>");
    }

    @Test
    void style_withPlaceItems_isAllowed() {
        assertThat(rule.apply("<div style=\"display: grid; place-items: center;\">text</div>"))
                .isEqualTo("<div style=\"display: grid; place-items: center;\">text</div>");
    }

    @Test
    void style_withGridAutoFlow_isAllowed() {
        assertThat(rule.apply("<div style=\"display: grid; grid-auto-flow: column;\">text</div>"))
                .isEqualTo("<div style=\"display: grid; grid-auto-flow: column;\">text</div>");
    }

    @Test
    void style_withUserSelect_isAllowed() {
        assertThat(rule.apply("<div style=\"user-select: none;\">text</div>"))
                .isEqualTo("<div style=\"user-select: none;\">text</div>");
    }

    @Test
    void style_withWebkitUserSelect_isAllowed() {
        assertThat(rule.apply("<div style=\"-webkit-user-select: none;\">text</div>"))
                .isEqualTo("<div style=\"-webkit-user-select: none;\">text</div>");
    }

    @Test
    void style_withScrollBehavior_isAllowed() {
        assertThat(rule.apply("<div style=\"scroll-behavior: smooth;\">text</div>"))
                .isEqualTo("<div style=\"scroll-behavior: smooth;\">text</div>");
    }

    @Test
    void style_withTextOrientation_isAllowed() {
        assertThat(rule.apply("<p style=\"writing-mode: vertical-rl; text-orientation: mixed;\">text</p>"))
                .isEqualTo("<p style=\"writing-mode: vertical-rl; text-orientation: mixed;\">text</p>");
    }

    @Test
    void style_withRubyPosition_isAllowed() {
        assertThat(rule.apply("<ruby style=\"ruby-position: over;\">kanji<rt>reading</rt></ruby>"))
                .isEqualTo("<ruby style=\"ruby-position: over;\">kanji<rt>reading</rt></ruby>");
    }

    @Test
    void style_withRubyAlign_isAllowed() {
        assertThat(rule.apply("<ruby style=\"ruby-align: center;\">kanji<rt>reading</rt></ruby>"))
                .isEqualTo("<ruby style=\"ruby-align: center;\">kanji<rt>reading</rt></ruby>");
    }

    @Test
    void style_withWritingMode_isAllowed() {
        assertThat(rule.apply("<p style=\"writing-mode: vertical-rl;\">vertical text</p>"))
                .isEqualTo("<p style=\"writing-mode: vertical-rl;\">vertical text</p>");
    }

    @Test
    void style_withObjectFit_isAllowed() {
        assertThat(rule.apply("<img src=\"/img.jpg\" alt=\"\" style=\"object-fit: cover;\">"))
                .isEqualTo("<img src=\"/img.jpg\" alt=\"\" style=\"object-fit: cover;\">");
    }

    @Test
    void style_withObjectPosition_isAllowed() {
        assertThat(rule.apply("<img src=\"/img.jpg\" alt=\"\" style=\"object-position: center top;\">"))
                .isEqualTo("<img src=\"/img.jpg\" alt=\"\" style=\"object-position: center top;\">");
    }

    @Test
    void style_withAspectRatio_isAllowed() {
        assertThat(rule.apply("<div style=\"aspect-ratio: 16/9;\">content</div>"))
                .isEqualTo("<div style=\"aspect-ratio: 16/9;\">content</div>");
    }

    @Test
    void style_withOutline_isAllowed() {
        assertThat(rule.apply("<div style=\"outline: none;\">content</div>"))
                .isEqualTo("<div style=\"outline: none;\">content</div>");
    }

    @Test
    void style_withTransition_isAllowed() {
        assertThat(rule.apply("<div style=\"transition: all 0.3s ease;\">content</div>"))
                .isEqualTo("<div style=\"transition: all 0.3s ease;\">content</div>");
    }

    @Test
    void style_withTransform_isAllowed() {
        assertThat(rule.apply("<img src=\"/img.jpg\" alt=\"\" style=\"transform: rotate(45deg);\">"))
                .isEqualTo("<img src=\"/img.jpg\" alt=\"\" style=\"transform: rotate(45deg);\">");
    }

    @Test
    void style_withFilter_isAllowed() {
        assertThat(rule.apply("<img src=\"/img.jpg\" alt=\"\" style=\"filter: blur(4px);\">"))
                .isEqualTo("<img src=\"/img.jpg\" alt=\"\" style=\"filter: blur(4px);\">");
    }

    @Test
    void style_withFilter_dangerousUrl_isRemoved() {
        // filter: url() with a dangerous URL must be blocked
        assertThat(rule.apply("<div style=\"filter: url(javascript:alert(1));\">text</div>"))
                .isEqualTo("<div>text</div>");
    }

    @Test
    void style_withCursor_isAllowed() {
        assertThat(rule.apply("<span style=\"cursor: pointer;\">text</span>"))
                .isEqualTo("<span style=\"cursor: pointer;\">text</span>");
    }

    @Test
    void style_withAnimation_isAllowed() {
        assertThat(rule.apply("<div style=\"animation: fadeIn 1s ease;\">text</div>"))
                .isEqualTo("<div style=\"animation: fadeIn 1s ease;\">text</div>");
    }

    @Test
    void style_withAnimationName_isAllowed() {
        assertThat(rule.apply("<div style=\"animation-name: slideIn;\">text</div>"))
                .isEqualTo("<div style=\"animation-name: slideIn;\">text</div>");
    }

    @Test
    void style_withAnimationDuration_isAllowed() {
        assertThat(rule.apply("<div style=\"animation-duration: 0.3s;\">text</div>"))
                .isEqualTo("<div style=\"animation-duration: 0.3s;\">text</div>");
    }

    @Test
    void style_withAnimationPlayState_isAllowed() {
        assertThat(rule.apply("<div style=\"animation-play-state: paused;\">text</div>"))
                .isEqualTo("<div style=\"animation-play-state: paused;\">text</div>");
    }

    @Test
    void style_withAnimationComposition_isAllowed() {
        assertThat(rule.apply("<div style=\"animation-composition: accumulate;\">text</div>"))
                .isEqualTo("<div style=\"animation-composition: accumulate;\">text</div>");
    }

    @Test
    void style_withAnimationTimeline_isAllowed() {
        assertThat(rule.apply("<div style=\"animation-timeline: scroll();\">text</div>"))
                .isEqualTo("<div style=\"animation-timeline: scroll();\">text</div>");
    }

    @Test
    void style_withAnimationRange_isAllowed() {
        assertThat(rule.apply("<div style=\"animation-range: entry 10% exit 90%;\">text</div>"))
                .isEqualTo("<div style=\"animation-range: entry 10% exit 90%;\">text</div>");
    }

    @Test
    void style_withAnimationRangeStart_isAllowed() {
        assertThat(rule.apply("<div style=\"animation-range-start: entry 20%;\">text</div>"))
                .isEqualTo("<div style=\"animation-range-start: entry 20%;\">text</div>");
    }

    @Test
    void style_withAnimationRangeEnd_isAllowed() {
        assertThat(rule.apply("<div style=\"animation-range-end: exit 80%;\">text</div>"))
                .isEqualTo("<div style=\"animation-range-end: exit 80%;\">text</div>");
    }

    @Test
    void style_withScrollTimeline_isAllowed() {
        assertThat(rule.apply("<div style=\"scroll-timeline: --my-timeline block;\">text</div>"))
                .isEqualTo("<div style=\"scroll-timeline: --my-timeline block;\">text</div>");
    }

    @Test
    void style_withScrollTimelineName_isAllowed() {
        assertThat(rule.apply("<div style=\"scroll-timeline-name: --my-timeline;\">text</div>"))
                .isEqualTo("<div style=\"scroll-timeline-name: --my-timeline;\">text</div>");
    }

    @Test
    void style_withScrollTimelineAxis_isAllowed() {
        assertThat(rule.apply("<div style=\"scroll-timeline-axis: block;\">text</div>"))
                .isEqualTo("<div style=\"scroll-timeline-axis: block;\">text</div>");
    }

    @Test
    void style_withViewTimeline_isAllowed() {
        assertThat(rule.apply("<div style=\"view-timeline: --reveal block;\">text</div>"))
                .isEqualTo("<div style=\"view-timeline: --reveal block;\">text</div>");
    }

    @Test
    void style_withViewTimelineName_isAllowed() {
        assertThat(rule.apply("<div style=\"view-timeline-name: --reveal;\">text</div>"))
                .isEqualTo("<div style=\"view-timeline-name: --reveal;\">text</div>");
    }

    @Test
    void style_withViewTimelineAxis_isAllowed() {
        assertThat(rule.apply("<div style=\"view-timeline-axis: inline;\">text</div>"))
                .isEqualTo("<div style=\"view-timeline-axis: inline;\">text</div>");
    }

    @Test
    void style_withViewTimelineInset_isAllowed() {
        assertThat(rule.apply("<div style=\"view-timeline-inset: 20px;\">text</div>"))
                .isEqualTo("<div style=\"view-timeline-inset: 20px;\">text</div>");
    }

    @Test
    void style_withZoom_isAllowed() {
        assertThat(rule.apply("<div style=\"zoom: 1.5;\">text</div>"))
                .isEqualTo("<div style=\"zoom: 1.5;\">text</div>");
    }

    // background longhand / blend
    @Test
    void style_withBackgroundPositionX_isAllowed() {
        assertThat(rule.apply("<div style=\"background-position-x: center;\">text</div>"))
                .isEqualTo("<div style=\"background-position-x: center;\">text</div>");
    }

    @Test
    void style_withBackgroundPositionY_isAllowed() {
        assertThat(rule.apply("<div style=\"background-position-y: 20%;\">text</div>"))
                .isEqualTo("<div style=\"background-position-y: 20%;\">text</div>");
    }

    @Test
    void style_withBackgroundBlendMode_isAllowed() {
        assertThat(rule.apply("<div style=\"background-blend-mode: multiply;\">text</div>"))
                .isEqualTo("<div style=\"background-blend-mode: multiply;\">text</div>");
    }

    // font variation / palette
    @Test
    void style_withFontVariationSettings_isAllowed() {
        assertThat(rule.apply("<div style=\"font-variation-settings: 'wght' 700;\">text</div>"))
                .isEqualTo("<div style=\"font-variation-settings: &#x27;wght&#x27; 700;\">text</div>");
    }

    @Test
    void style_withFontPalette_isAllowed() {
        assertThat(rule.apply("<div style=\"font-palette: dark;\">text</div>"))
                .isEqualTo("<div style=\"font-palette: dark;\">text</div>");
    }

    // text layout
    @Test
    void style_withTextAlignLast_isAllowed() {
        assertThat(rule.apply("<p style=\"text-align-last: justify;\">text</p>"))
                .isEqualTo("<p style=\"text-align-last: justify;\">text</p>");
    }

    @Test
    void style_withTextJustify_isAllowed() {
        assertThat(rule.apply("<p style=\"text-justify: inter-word;\">text</p>"))
                .isEqualTo("<p style=\"text-justify: inter-word;\">text</p>");
    }

    @Test
    void style_withTextWrapMode_isAllowed() {
        assertThat(rule.apply("<p style=\"text-wrap-mode: nowrap;\">text</p>"))
                .isEqualTo("<p style=\"text-wrap-mode: nowrap;\">text</p>");
    }

    @Test
    void style_withTextWrapStyle_isAllowed() {
        assertThat(rule.apply("<p style=\"text-wrap-style: balance;\">text</p>"))
                .isEqualTo("<p style=\"text-wrap-style: balance;\">text</p>");
    }

    @Test
    void style_withWhiteSpaceCollapse_isAllowed() {
        assertThat(rule.apply("<p style=\"white-space-collapse: preserve;\">text</p>"))
                .isEqualTo("<p style=\"white-space-collapse: preserve;\">text</p>");
    }

    @Test
    void style_withLineBreak_isAllowed() {
        assertThat(rule.apply("<p style=\"line-break: strict;\">text</p>"))
                .isEqualTo("<p style=\"line-break: strict;\">text</p>");
    }

    @Test
    void style_withHyphenateCharacter_isAllowed() {
        assertThat(rule.apply("<p style=\"hyphenate-character: auto;\">text</p>"))
                .isEqualTo("<p style=\"hyphenate-character: auto;\">text</p>");
    }

    @Test
    void style_withHyphenateLimitChars_isAllowed() {
        assertThat(rule.apply("<p style=\"hyphenate-limit-chars: 6 3 2;\">text</p>"))
                .isEqualTo("<p style=\"hyphenate-limit-chars: 6 3 2;\">text</p>");
    }

    // grid longhands
    @Test
    void style_withGridColumnStart_isAllowed() {
        assertThat(rule.apply("<div style=\"grid-column-start: 1;\">text</div>"))
                .isEqualTo("<div style=\"grid-column-start: 1;\">text</div>");
    }

    @Test
    void style_withGridColumnEnd_isAllowed() {
        assertThat(rule.apply("<div style=\"grid-column-end: 3;\">text</div>"))
                .isEqualTo("<div style=\"grid-column-end: 3;\">text</div>");
    }

    @Test
    void style_withGridRowStart_isAllowed() {
        assertThat(rule.apply("<div style=\"grid-row-start: 2;\">text</div>"))
                .isEqualTo("<div style=\"grid-row-start: 2;\">text</div>");
    }

    @Test
    void style_withGridRowEnd_isAllowed() {
        assertThat(rule.apply("<div style=\"grid-row-end: 4;\">text</div>"))
                .isEqualTo("<div style=\"grid-row-end: 4;\">text</div>");
    }

    // motion path
    @Test
    void style_withOffsetPosition_isAllowed() {
        assertThat(rule.apply("<div style=\"offset-position: center;\">text</div>"))
                .isEqualTo("<div style=\"offset-position: center;\">text</div>");
    }

    // transition
    @Test
    void style_withTransitionBehavior_isAllowed() {
        assertThat(rule.apply("<div style=\"transition-behavior: allow-discrete;\">text</div>"))
                .isEqualTo("<div style=\"transition-behavior: allow-discrete;\">text</div>");
    }

    // transition longhands
    @Test
    void style_withTransitionProperty_isAllowed() {
        assertThat(rule.apply("<div style=\"transition-property: opacity;\">text</div>"))
                .isEqualTo("<div style=\"transition-property: opacity;\">text</div>");
    }

    @Test
    void style_withTransitionDuration_isAllowed() {
        assertThat(rule.apply("<div style=\"transition-duration: 0.3s;\">text</div>"))
                .isEqualTo("<div style=\"transition-duration: 0.3s;\">text</div>");
    }

    @Test
    void style_withTransitionTimingFunction_isAllowed() {
        assertThat(rule.apply("<div style=\"transition-timing-function: ease-in-out;\">text</div>"))
                .isEqualTo("<div style=\"transition-timing-function: ease-in-out;\">text</div>");
    }

    @Test
    void style_withTransitionDelay_isAllowed() {
        assertThat(rule.apply("<div style=\"transition-delay: 0.1s;\">text</div>"))
                .isEqualTo("<div style=\"transition-delay: 0.1s;\">text</div>");
    }

    // form / UI
    @Test
    void style_withAccentColor_isAllowed() {
        assertThat(rule.apply("<div style=\"accent-color: #3498db;\">text</div>"))
                .isEqualTo("<div style=\"accent-color: #3498db;\">text</div>");
    }

    @Test
    void style_withCaretColor_isAllowed() {
        assertThat(rule.apply("<div style=\"caret-color: red;\">text</div>"))
                .isEqualTo("<div style=\"caret-color: red;\">text</div>");
    }

    @Test
    void style_withAppearanceNone_isAllowed() {
        assertThat(rule.apply("<div style=\"appearance: none;\">text</div>"))
                .isEqualTo("<div style=\"appearance: none;\">text</div>");
    }

    @Test
    void style_withWebkitAppearanceNone_isAllowed() {
        assertThat(rule.apply("<div style=\"-webkit-appearance: none;\">text</div>"))
                .isEqualTo("<div style=\"-webkit-appearance: none;\">text</div>");
    }

    @Test
    void style_withWebkitTapHighlightColor_isAllowed() {
        assertThat(rule.apply("<div style=\"-webkit-tap-highlight-color: transparent;\">text</div>"))
                .isEqualTo("<div style=\"-webkit-tap-highlight-color: transparent;\">text</div>");
    }

    @Test
    void style_withWebkitTouchCallout_isAllowed() {
        assertThat(rule.apply("<div style=\"-webkit-touch-callout: none;\">text</div>"))
                .isEqualTo("<div style=\"-webkit-touch-callout: none;\">text</div>");
    }

    @Test
    void style_withResize_isAllowed() {
        assertThat(rule.apply("<div style=\"resize: both;\">text</div>"))
                .isEqualTo("<div style=\"resize: both;\">text</div>");
    }

    @Test
    void style_withScrollbarWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"scrollbar-width: thin;\">text</div>"))
                .isEqualTo("<div style=\"scrollbar-width: thin;\">text</div>");
    }

    @Test
    void style_withScrollbarColor_isAllowed() {
        assertThat(rule.apply("<div style=\"scrollbar-color: #888 #f1f1f1;\">text</div>"))
                .isEqualTo("<div style=\"scrollbar-color: #888 #f1f1f1;\">text</div>");
    }

    @Test
    void style_withScrollbarGutter_isAllowed() {
        assertThat(rule.apply("<div style=\"scrollbar-gutter: stable;\">text</div>"))
                .isEqualTo("<div style=\"scrollbar-gutter: stable;\">text</div>");
    }

    // shape
    @Test
    void style_withShapeImageThreshold_isAllowed() {
        assertThat(rule.apply("<div style=\"shape-image-threshold: 0.5;\">text</div>"))
                .isEqualTo("<div style=\"shape-image-threshold: 0.5;\">text</div>");
    }

    // list
    @Test
    void style_withQuotes_isAllowed() {
        assertThat(rule.apply("<blockquote style=\"quotes: none;\">text</blockquote>"))
                .isEqualTo("<blockquote style=\"quotes: none;\">text</blockquote>");
    }

    // SVG CSS properties — verified via span (SVG elements can be added via constructor;
    // here we confirm the CSS property itself is permitted and passes through the sanitizer)
    @Test
    void style_svgFill_isAllowed() {
        assertThat(rule.apply("<span style=\"fill: #e74c3c;\">text</span>"))
                .isEqualTo("<span style=\"fill: #e74c3c;\">text</span>");
    }

    @Test
    void style_svgFillOpacity_isAllowed() {
        assertThat(rule.apply("<span style=\"fill-opacity: 0.8;\">text</span>"))
                .isEqualTo("<span style=\"fill-opacity: 0.8;\">text</span>");
    }

    @Test
    void style_svgStroke_isAllowed() {
        assertThat(rule.apply("<span style=\"stroke: blue;\">text</span>"))
                .isEqualTo("<span style=\"stroke: blue;\">text</span>");
    }

    @Test
    void style_svgStrokeWidth_isAllowed() {
        assertThat(rule.apply("<span style=\"stroke-width: 2;\">text</span>"))
                .isEqualTo("<span style=\"stroke-width: 2;\">text</span>");
    }

    @Test
    void style_svgStrokeDasharray_isAllowed() {
        assertThat(rule.apply("<span style=\"stroke-dasharray: 5 3;\">text</span>"))
                .isEqualTo("<span style=\"stroke-dasharray: 5 3;\">text</span>");
    }

    @Test
    void style_svgStrokeLinecap_isAllowed() {
        assertThat(rule.apply("<span style=\"stroke-linecap: round;\">text</span>"))
                .isEqualTo("<span style=\"stroke-linecap: round;\">text</span>");
    }

    @Test
    void style_svgStrokeLinejoin_isAllowed() {
        assertThat(rule.apply("<span style=\"stroke-linejoin: bevel;\">text</span>"))
                .isEqualTo("<span style=\"stroke-linejoin: bevel;\">text</span>");
    }

    @Test
    void style_svgStrokeMiterlimit_isAllowed() {
        assertThat(rule.apply("<span style=\"stroke-miterlimit: 4;\">text</span>"))
                .isEqualTo("<span style=\"stroke-miterlimit: 4;\">text</span>");
    }

    @Test
    void style_svgStrokeOpacity_isAllowed() {
        assertThat(rule.apply("<span style=\"stroke-opacity: 0.5;\">text</span>"))
                .isEqualTo("<span style=\"stroke-opacity: 0.5;\">text</span>");
    }

    @Test
    void style_svgStrokeDashoffset_isAllowed() {
        assertThat(rule.apply("<span style=\"stroke-dashoffset: 10;\">text</span>"))
                .isEqualTo("<span style=\"stroke-dashoffset: 10;\">text</span>");
    }

    @Test
    void style_svgFillRule_isAllowed() {
        assertThat(rule.apply("<span style=\"fill-rule: evenodd;\">text</span>"))
                .isEqualTo("<span style=\"fill-rule: evenodd;\">text</span>");
    }

    @Test
    void style_svgClipRule_isAllowed() {
        assertThat(rule.apply("<span style=\"clip-rule: nonzero;\">text</span>"))
                .isEqualTo("<span style=\"clip-rule: nonzero;\">text</span>");
    }

    @Test
    void style_svgPaintOrder_isAllowed() {
        assertThat(rule.apply("<span style=\"paint-order: stroke fill;\">text</span>"))
                .isEqualTo("<span style=\"paint-order: stroke fill;\">text</span>");
    }

    @Test
    void style_svgTextAnchor_isAllowed() {
        assertThat(rule.apply("<span style=\"text-anchor: middle;\">text</span>"))
                .isEqualTo("<span style=\"text-anchor: middle;\">text</span>");
    }

    @Test
    void style_svgDominantBaseline_isAllowed() {
        assertThat(rule.apply("<span style=\"dominant-baseline: middle;\">text</span>"))
                .isEqualTo("<span style=\"dominant-baseline: middle;\">text</span>");
    }

    @Test
    void style_svgAlignmentBaseline_isAllowed() {
        assertThat(rule.apply("<span style=\"alignment-baseline: central;\">text</span>"))
                .isEqualTo("<span style=\"alignment-baseline: central;\">text</span>");
    }

    @Test
    void style_svgVectorEffect_isAllowed() {
        assertThat(rule.apply("<span style=\"vector-effect: non-scaling-stroke;\">text</span>"))
                .isEqualTo("<span style=\"vector-effect: non-scaling-stroke;\">text</span>");
    }

    @Test
    void style_svgStopColor_isAllowed() {
        assertThat(rule.apply("<span style=\"stop-color: #ff0000;\">text</span>"))
                .isEqualTo("<span style=\"stop-color: #ff0000;\">text</span>");
    }

    @Test
    void style_svgStopOpacity_isAllowed() {
        assertThat(rule.apply("<span style=\"stop-opacity: 0.8;\">text</span>"))
                .isEqualTo("<span style=\"stop-opacity: 0.8;\">text</span>");
    }

    @Test
    void style_svgFloodColor_isAllowed() {
        assertThat(rule.apply("<span style=\"flood-color: #3498db;\">text</span>"))
                .isEqualTo("<span style=\"flood-color: #3498db;\">text</span>");
    }

    @Test
    void style_svgFloodOpacity_isAllowed() {
        assertThat(rule.apply("<span style=\"flood-opacity: 0.5;\">text</span>"))
                .isEqualTo("<span style=\"flood-opacity: 0.5;\">text</span>");
    }

    @Test
    void style_svgLightingColor_isAllowed() {
        assertThat(rule.apply("<span style=\"lighting-color: white;\">text</span>"))
                .isEqualTo("<span style=\"lighting-color: white;\">text</span>");
    }

    // SVG geometry CSS properties
    @Test
    void style_svgD_isAllowed() {
        assertThat(rule.apply("<span style=\"d: path('M0,0 L100,100');\">text</span>"))
                .isEqualTo("<span style=\"d: path(&#x27;M0,0 L100,100&#x27;);\">text</span>");
    }

    @Test
    void style_svgCx_isAllowed() {
        assertThat(rule.apply("<span style=\"cx: 50px;\">text</span>"))
                .isEqualTo("<span style=\"cx: 50px;\">text</span>");
    }

    @Test
    void style_svgCy_isAllowed() {
        assertThat(rule.apply("<span style=\"cy: 50px;\">text</span>"))
                .isEqualTo("<span style=\"cy: 50px;\">text</span>");
    }

    @Test
    void style_svgR_isAllowed() {
        assertThat(rule.apply("<span style=\"r: 40px;\">text</span>"))
                .isEqualTo("<span style=\"r: 40px;\">text</span>");
    }

    @Test
    void style_svgRx_isAllowed() {
        assertThat(rule.apply("<span style=\"rx: 10px;\">text</span>"))
                .isEqualTo("<span style=\"rx: 10px;\">text</span>");
    }

    @Test
    void style_svgRy_isAllowed() {
        assertThat(rule.apply("<span style=\"ry: 10px;\">text</span>"))
                .isEqualTo("<span style=\"ry: 10px;\">text</span>");
    }

    @Test
    void style_svgX_isAllowed() {
        assertThat(rule.apply("<span style=\"x: 20px;\">text</span>"))
                .isEqualTo("<span style=\"x: 20px;\">text</span>");
    }

    @Test
    void style_svgY_isAllowed() {
        assertThat(rule.apply("<span style=\"y: 20px;\">text</span>"))
                .isEqualTo("<span style=\"y: 20px;\">text</span>");
    }

    @Test
    void style_svgBaselineShift_isAllowed() {
        assertThat(rule.apply("<span style=\"baseline-shift: super;\">text</span>"))
                .isEqualTo("<span style=\"baseline-shift: super;\">text</span>");
    }

    @Test
    void style_svgShapeRendering_isAllowed() {
        assertThat(rule.apply("<span style=\"shape-rendering: crispEdges;\">text</span>"))
                .isEqualTo("<span style=\"shape-rendering: crispEdges;\">text</span>");
    }

    @Test
    void style_svgColorRendering_isAllowed() {
        assertThat(rule.apply("<span style=\"color-rendering: optimizeQuality;\">text</span>"))
                .isEqualTo("<span style=\"color-rendering: optimizeQuality;\">text</span>");
    }

    @Test
    void style_svgColorInterpolation_isAllowed() {
        assertThat(rule.apply("<span style=\"color-interpolation: linearRGB;\">text</span>"))
                .isEqualTo("<span style=\"color-interpolation: linearRGB;\">text</span>");
    }

    @Test
    void style_svgColorInterpolationFilters_isAllowed() {
        assertThat(rule.apply("<span style=\"color-interpolation-filters: linearRGB;\">text</span>"))
                .isEqualTo("<span style=\"color-interpolation-filters: linearRGB;\">text</span>");
    }

    @Test
    void style_withTextBox_isAllowed() {
        assertThat(rule.apply("<p style=\"text-box: trim-both cap alphabetic;\">text</p>"))
                .isEqualTo("<p style=\"text-box: trim-both cap alphabetic;\">text</p>");
    }

    @Test
    void style_withTextBoxTrim_isAllowed() {
        assertThat(rule.apply("<p style=\"text-box-trim: both;\">text</p>"))
                .isEqualTo("<p style=\"text-box-trim: both;\">text</p>");
    }

    @Test
    void style_withTextBoxEdge_isAllowed() {
        assertThat(rule.apply("<p style=\"text-box-edge: cap alphabetic;\">text</p>"))
                .isEqualTo("<p style=\"text-box-edge: cap alphabetic;\">text</p>");
    }

    @Test
    void style_svgMarkerStart_isAllowed() {
        assertThat(rule.apply("<span style=\"marker-start: url(#arrow);\">text</span>"))
                .isEqualTo("<span style=\"marker-start: url(#arrow);\">text</span>");
    }

    @Test
    void style_svgMarkerMid_isAllowed() {
        assertThat(rule.apply("<span style=\"marker-mid: url(#dot);\">text</span>"))
                .isEqualTo("<span style=\"marker-mid: url(#dot);\">text</span>");
    }

    @Test
    void style_svgMarkerEnd_isAllowed() {
        assertThat(rule.apply("<span style=\"marker-end: url(#arrow);\">text</span>"))
                .isEqualTo("<span style=\"marker-end: url(#arrow);\">text</span>");
    }

    @Test
    void style_svgMarker_isAllowed() {
        assertThat(rule.apply("<span style=\"marker: url(#arrow);\">text</span>"))
                .isEqualTo("<span style=\"marker: url(#arrow);\">text</span>");
    }

    @Test
    void style_withClipPath_isAllowed() {
        assertThat(rule.apply("<div style=\"clip-path: circle(50%);\">text</div>"))
                .isEqualTo("<div style=\"clip-path: circle(50%);\">text</div>");
    }

    @Test
    void style_withBackgroundClip_isAllowed() {
        assertThat(rule.apply("<div style=\"background-clip: text;\">text</div>"))
                .isEqualTo("<div style=\"background-clip: text;\">text</div>");
    }

    @Test
    void style_withWebkitBackgroundClip_isAllowed() {
        assertThat(rule.apply("<div style=\"-webkit-background-clip: text;\">text</div>"))
                .isEqualTo("<div style=\"-webkit-background-clip: text;\">text</div>");
    }

    @Test
    void style_withTextDecorationColor_isAllowed() {
        assertThat(rule.apply("<span style=\"text-decoration-color: red;\">text</span>"))
                .isEqualTo("<span style=\"text-decoration-color: red;\">text</span>");
    }

    @Test
    void style_withTextDecorationLine_isAllowed() {
        assertThat(rule.apply("<span style=\"text-decoration-line: underline;\">text</span>"))
                .isEqualTo("<span style=\"text-decoration-line: underline;\">text</span>");
    }

    @Test
    void style_withTextDecorationStyle_isAllowed() {
        assertThat(rule.apply("<span style=\"text-decoration-style: wavy;\">text</span>"))
                .isEqualTo("<span style=\"text-decoration-style: wavy;\">text</span>");
    }

    @Test
    void style_withTextDecorationThickness_isAllowed() {
        assertThat(rule.apply("<span style=\"text-decoration-thickness: 2px;\">text</span>"))
                .isEqualTo("<span style=\"text-decoration-thickness: 2px;\">text</span>");
    }

    @Test
    void style_withTextUnderlineOffset_isAllowed() {
        assertThat(rule.apply("<span style=\"text-underline-offset: 4px;\">text</span>"))
                .isEqualTo("<span style=\"text-underline-offset: 4px;\">text</span>");
    }

    @Test
    void style_withBorderImage_safeUrl_isAllowed() {
        assertThat(rule.apply("<div style=\"border-image-source: url(/border.png);\">text</div>"))
                .isEqualTo("<div style=\"border-image-source: url(/border.png);\">text</div>");
    }

    @Test
    void style_withBorderImage_dangerousUrl_isRemoved() {
        assertThat(rule.apply("<div style=\"border-image-source: url(javascript:alert(1));\">text</div>"))
                .isEqualTo("<div>text</div>");
    }

    @Test
    void style_withBorderImageSlice_isAllowed() {
        assertThat(rule.apply("<div style=\"border-image-slice: 30;\">text</div>"))
                .isEqualTo("<div style=\"border-image-slice: 30;\">text</div>");
    }

    @Test
    void style_withTextEmphasis_isAllowed() {
        assertThat(rule.apply("<p style=\"text-emphasis: filled circle red;\">text</p>"))
                .isEqualTo("<p style=\"text-emphasis: filled circle red;\">text</p>");
    }

    @Test
    void style_withTextEmphasisPosition_isAllowed() {
        assertThat(rule.apply("<p style=\"text-emphasis-position: over right;\">text</p>"))
                .isEqualTo("<p style=\"text-emphasis-position: over right;\">text</p>");
    }

    @Test
    void style_withContain_isAllowed() {
        assertThat(rule.apply("<div style=\"contain: layout paint;\">text</div>"))
                .isEqualTo("<div style=\"contain: layout paint;\">text</div>");
    }

    @Test
    void style_withContainIntrinsicSize_isAllowed() {
        assertThat(rule.apply("<div style=\"contain-intrinsic-size: 300px 200px;\">text</div>"))
                .isEqualTo("<div style=\"contain-intrinsic-size: 300px 200px;\">text</div>");
    }

    @Test
    void style_withContainIntrinsicWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"contain-intrinsic-width: 300px;\">text</div>"))
                .isEqualTo("<div style=\"contain-intrinsic-width: 300px;\">text</div>");
    }

    @Test
    void style_withContainIntrinsicHeight_isAllowed() {
        assertThat(rule.apply("<div style=\"contain-intrinsic-height: 200px;\">text</div>"))
                .isEqualTo("<div style=\"contain-intrinsic-height: 200px;\">text</div>");
    }

    @Test
    void style_withContainIntrinsicInlineSize_isAllowed() {
        assertThat(rule.apply("<div style=\"contain-intrinsic-inline-size: 300px;\">text</div>"))
                .isEqualTo("<div style=\"contain-intrinsic-inline-size: 300px;\">text</div>");
    }

    @Test
    void style_withContainIntrinsicBlockSize_isAllowed() {
        assertThat(rule.apply("<div style=\"contain-intrinsic-block-size: 200px;\">text</div>"))
                .isEqualTo("<div style=\"contain-intrinsic-block-size: 200px;\">text</div>");
    }

    @Test
    void style_withPageBreakInside_isAllowed() {
        assertThat(rule.apply("<div style=\"page-break-inside: avoid;\">text</div>"))
                .isEqualTo("<div style=\"page-break-inside: avoid;\">text</div>");
    }

    @Test
    void style_withFontVariantAlternates_isAllowed() {
        assertThat(rule.apply("<p style=\"font-variant-alternates: historical-forms;\">text</p>"))
                .isEqualTo("<p style=\"font-variant-alternates: historical-forms;\">text</p>");
    }

    @Test
    void style_withFontVariantPosition_isAllowed() {
        assertThat(rule.apply("<p style=\"font-variant-position: super;\">text</p>"))
                .isEqualTo("<p style=\"font-variant-position: super;\">text</p>");
    }

    @Test
    void style_withFontVariantLigatures_isAllowed() {
        assertThat(rule.apply("<p style=\"font-variant-ligatures: common-ligatures;\">text</p>"))
                .isEqualTo("<p style=\"font-variant-ligatures: common-ligatures;\">text</p>");
    }

    @Test
    void style_withFontVariantEastAsian_isAllowed() {
        assertThat(rule.apply("<p style=\"font-variant-east-asian: ruby;\">text</p>"))
                .isEqualTo("<p style=\"font-variant-east-asian: ruby;\">text</p>");
    }

    @Test
    void style_withImageRendering_isAllowed() {
        assertThat(rule.apply("<img src=\"/sprite.png\" style=\"image-rendering: pixelated;\">"))
                .isEqualTo("<img src=\"/sprite.png\" style=\"image-rendering: pixelated;\">");
    }

    @Test
    void style_withImageOrientation_isAllowed() {
        assertThat(rule.apply("<img src=\"/photo.jpg\" style=\"image-orientation: from-image;\">"))
                .isEqualTo("<img src=\"/photo.jpg\" style=\"image-orientation: from-image;\">");
    }

    @Test
    void style_withInterpolateSize_isAllowed() {
        assertThat(rule.apply("<div style=\"interpolate-size: allow-keywords;\">text</div>"))
                .isEqualTo("<div style=\"interpolate-size: allow-keywords;\">text</div>");
    }

    @Test
    void style_withListStyleImage_safeUrl_isAllowed() {
        assertThat(rule.apply("<ul style=\"list-style-image: url(/bullet.svg);\"><li>item</li></ul>"))
                .isEqualTo("<ul style=\"list-style-image: url(/bullet.svg);\"><li>item</li></ul>");
    }

    @Test
    void style_withListStyleImage_dangerousUrl_isRemoved() {
        assertThat(rule.apply("<ul style=\"list-style-image: url(javascript:alert(1));\"><li>item</li></ul>"))
                .isEqualTo("<ul><li>item</li></ul>");
    }

    @Test
    void style_withInitialLetter_isAllowed() {
        assertThat(rule.apply("<p style=\"initial-letter: 3;\">text</p>"))
                .isEqualTo("<p style=\"initial-letter: 3;\">text</p>");
    }

    @Test
    void style_withTouchAction_isAllowed() {
        assertThat(rule.apply("<div style=\"touch-action: pan-y;\">text</div>"))
                .isEqualTo("<div style=\"touch-action: pan-y;\">text</div>");
    }

    @Test
    void style_withMaskImage_safeUrl_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-image: url(/mask.svg);\">text</div>"))
                .isEqualTo("<div style=\"mask-image: url(/mask.svg);\">text</div>");
    }

    @Test
    void style_withMaskImage_dangerousUrl_isRemoved() {
        assertThat(rule.apply("<div style=\"mask-image: url(javascript:alert(1));\">text</div>"))
                .isEqualTo("<div>text</div>");
    }

    @Test
    void style_withMaskSize_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-size: cover;\">text</div>"))
                .isEqualTo("<div style=\"mask-size: cover;\">text</div>");
    }

    @Test
    void style_withTextDecorationSkipInk_isAllowed() {
        assertThat(rule.apply("<p style=\"text-decoration-skip-ink: auto;\">text</p>"))
                .isEqualTo("<p style=\"text-decoration-skip-ink: auto;\">text</p>");
    }

    @Test
    void style_withTextUnderlinePosition_isAllowed() {
        assertThat(rule.apply("<p style=\"text-underline-position: under;\">text</p>"))
                .isEqualTo("<p style=\"text-underline-position: under;\">text</p>");
    }

    @Test
    void style_withEmptyCells_isAllowed() {
        assertThat(rule.apply("<table style=\"empty-cells: hide;\"><tr><td></td></tr></table>"))
                .isEqualTo("<table style=\"empty-cells: hide;\"><tr><td></td></tr></table>");
    }

    @Test
    void style_withForcedColorAdjust_isAllowed() {
        assertThat(rule.apply("<div style=\"forced-color-adjust: none;\">text</div>"))
                .isEqualTo("<div style=\"forced-color-adjust: none;\">text</div>");
    }

    @Test
    void style_withOffsetPath_isAllowed() {
        // Single quotes inside the CSS value are escaped to &#x27; by escapeHtmlAttr.
        assertThat(rule.apply("<div style=\"offset-path: path('M0,0 L100,100');\">text</div>"))
                .isEqualTo("<div style=\"offset-path: path(&#x27;M0,0 L100,100&#x27;);\">text</div>");
    }

    @Test
    void style_withOffsetDistance_isAllowed() {
        assertThat(rule.apply("<div style=\"offset-distance: 50%;\">text</div>"))
                .isEqualTo("<div style=\"offset-distance: 50%;\">text</div>");
    }

    @Test
    void style_withIsolation_isAllowed() {
        assertThat(rule.apply("<div style=\"isolation: isolate;\">text</div>"))
                .isEqualTo("<div style=\"isolation: isolate;\">text</div>");
    }

    @Test
    void style_withTransformOrigin_isAllowed() {
        assertThat(rule.apply("<div style=\"transform: rotate(45deg); transform-origin: top left;\">text</div>"))
                .isEqualTo("<div style=\"transform: rotate(45deg); transform-origin: top left;\">text</div>");
    }

    @Test
    void style_withBackfaceVisibility_isAllowed() {
        assertThat(rule.apply("<div style=\"backface-visibility: hidden;\">text</div>"))
                .isEqualTo("<div style=\"backface-visibility: hidden;\">text</div>");
    }

    @Test
    void style_withTransformStyle_isAllowed() {
        assertThat(rule.apply("<div style=\"transform-style: preserve-3d;\">text</div>"))
                .isEqualTo("<div style=\"transform-style: preserve-3d;\">text</div>");
    }

    @Test
    void style_withPerspective_isAllowed() {
        assertThat(rule.apply("<div style=\"perspective: 800px;\">text</div>"))
                .isEqualTo("<div style=\"perspective: 800px;\">text</div>");
    }

    @Test
    void style_withBackdropFilter_isAllowed() {
        assertThat(rule.apply("<div style=\"backdrop-filter: blur(8px);\">text</div>"))
                .isEqualTo("<div style=\"backdrop-filter: blur(8px);\">text</div>");
    }

    @Test
    void style_withWebkitBackdropFilter_isAllowed() {
        assertThat(rule.apply("<div style=\"-webkit-backdrop-filter: blur(8px);\">text</div>"))
                .isEqualTo("<div style=\"-webkit-backdrop-filter: blur(8px);\">text</div>");
    }

    @Test
    void style_withFontStretch_isAllowed() {
        assertThat(rule.apply("<p style=\"font-stretch: condensed;\">text</p>"))
                .isEqualTo("<p style=\"font-stretch: condensed;\">text</p>");
    }

    @Test
    void style_withCounterSet_isAllowed() {
        assertThat(rule.apply("<li style=\"counter-set: section 5;\">item</li>"))
                .isEqualTo("<li style=\"counter-set: section 5;\">item</li>");
    }

    @Test
    void style_withContainer_isAllowed() {
        assertThat(rule.apply("<div style=\"container: sidebar / inline-size;\">text</div>"))
                .isEqualTo("<div style=\"container: sidebar / inline-size;\">text</div>");
    }

    @Test
    void style_withContainerType_isAllowed() {
        assertThat(rule.apply("<div style=\"container-type: inline-size;\">text</div>"))
                .isEqualTo("<div style=\"container-type: inline-size;\">text</div>");
    }

    @Test
    void style_withContentVisibility_isAllowed() {
        assertThat(rule.apply("<div style=\"content-visibility: auto;\">text</div>"))
                .isEqualTo("<div style=\"content-visibility: auto;\">text</div>");
    }

    @Test
    void style_withScrollPaddingInline_isAllowed() {
        assertThat(rule.apply("<div style=\"scroll-padding-inline-start: 80px;\">text</div>"))
                .isEqualTo("<div style=\"scroll-padding-inline-start: 80px;\">text</div>");
    }

    @Test
    void style_withScrollMarginBlock_isAllowed() {
        assertThat(rule.apply("<section style=\"scroll-margin-block-start: 80px;\">text</section>"))
                .isEqualTo("<section style=\"scroll-margin-block-start: 80px;\">text</section>");
    }

    @Test
    void style_withOverscrollBehaviorInline_isAllowed() {
        assertThat(rule.apply("<div style=\"overscroll-behavior-inline: none;\">text</div>"))
                .isEqualTo("<div style=\"overscroll-behavior-inline: none;\">text</div>");
    }

    @Test
    void style_withOverflowClipMargin_isAllowed() {
        assertThat(rule.apply("<div style=\"overflow: clip; overflow-clip-margin: 8px;\">text</div>"))
                .isEqualTo("<div style=\"overflow: clip; overflow-clip-margin: 8px;\">text</div>");
    }

    @Test
    void style_withMaskComposite_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-composite: intersect;\">text</div>"))
                .isEqualTo("<div style=\"mask-composite: intersect;\">text</div>");
    }

    @Test
    void style_withMaskClip_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-clip: padding-box;\">text</div>"))
                .isEqualTo("<div style=\"mask-clip: padding-box;\">text</div>");
    }

    @Test
    void style_withMaskPositionX_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-position-x: center;\">text</div>"))
                .isEqualTo("<div style=\"mask-position-x: center;\">text</div>");
    }

    @Test
    void style_withMaskPositionY_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-position-y: 50%;\">text</div>"))
                .isEqualTo("<div style=\"mask-position-y: 50%;\">text</div>");
    }

    @Test
    void style_withWebkitMaskClip_isAllowed() {
        assertThat(rule.apply("<div style=\"-webkit-mask-clip: content-box;\">text</div>"))
                .isEqualTo("<div style=\"-webkit-mask-clip: content-box;\">text</div>");
    }

    @Test
    void style_withWebkitMaskOrigin_isAllowed() {
        assertThat(rule.apply("<div style=\"-webkit-mask-origin: padding-box;\">text</div>"))
                .isEqualTo("<div style=\"-webkit-mask-origin: padding-box;\">text</div>");
    }

    @Test
    void style_withWebkitMaskComposite_isAllowed() {
        assertThat(rule.apply("<div style=\"-webkit-mask-composite: source-over;\">text</div>"))
                .isEqualTo("<div style=\"-webkit-mask-composite: source-over;\">text</div>");
    }

    // mask-border
    @Test
    void style_withMaskBorder_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-border: url(/mask.png) 30 stretch;\">text</div>"))
                .isEqualTo("<div style=\"mask-border: url(/mask.png) 30 stretch;\">text</div>");
    }

    @Test
    void style_withMaskBorderSource_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-border-source: url(/mask.png);\">text</div>"))
                .isEqualTo("<div style=\"mask-border-source: url(/mask.png);\">text</div>");
    }

    @Test
    void style_withMaskBorderSlice_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-border-slice: 30;\">text</div>"))
                .isEqualTo("<div style=\"mask-border-slice: 30;\">text</div>");
    }

    @Test
    void style_withMaskBorderWidth_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-border-width: 10px;\">text</div>"))
                .isEqualTo("<div style=\"mask-border-width: 10px;\">text</div>");
    }

    @Test
    void style_withMaskBorderOutset_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-border-outset: 5px;\">text</div>"))
                .isEqualTo("<div style=\"mask-border-outset: 5px;\">text</div>");
    }

    @Test
    void style_withMaskBorderRepeat_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-border-repeat: round;\">text</div>"))
                .isEqualTo("<div style=\"mask-border-repeat: round;\">text</div>");
    }

    @Test
    void style_withMaskBorderMode_isAllowed() {
        assertThat(rule.apply("<div style=\"mask-border-mode: luminance;\">text</div>"))
                .isEqualTo("<div style=\"mask-border-mode: luminance;\">text</div>");
    }

    @Test
    void style_withOffsetAnchor_isAllowed() {
        assertThat(rule.apply("<div style=\"offset-anchor: top left;\">text</div>"))
                .isEqualTo("<div style=\"offset-anchor: top left;\">text</div>");
    }

    @Test
    void style_withScrollPadding_isAllowed() {
        assertThat(rule.apply("<div style=\"scroll-padding-top: 80px;\">text</div>"))
                .isEqualTo("<div style=\"scroll-padding-top: 80px;\">text</div>");
    }

    @Test
    void style_withScrollMargin_isAllowed() {
        assertThat(rule.apply("<section style=\"scroll-margin-top: 80px;\">text</section>"))
                .isEqualTo("<section style=\"scroll-margin-top: 80px;\">text</section>");
    }

    @Test
    void style_withWebkitMaskImage_safeUrl_isAllowed() {
        assertThat(rule.apply("<div style=\"-webkit-mask-image: url(/mask.svg);\">text</div>"))
                .isEqualTo("<div style=\"-webkit-mask-image: url(/mask.svg);\">text</div>");
    }

    @Test
    void style_withWebkitTextStroke_isAllowed() {
        assertThat(rule.apply("<h1 style=\"-webkit-text-stroke: 1px black;\">text</h1>"))
                .isEqualTo("<h1 style=\"-webkit-text-stroke: 1px black;\">text</h1>");
    }

    @Test
    void style_withWebkitTextFillColor_isAllowed() {
        assertThat(rule.apply("<h1 style=\"-webkit-text-fill-color: transparent;\">text</h1>"))
                .isEqualTo("<h1 style=\"-webkit-text-fill-color: transparent;\">text</h1>");
    }

    @Test
    void style_withFontSynthesis_isAllowed() {
        assertThat(rule.apply("<p style=\"font-synthesis: none;\">text</p>"))
                .isEqualTo("<p style=\"font-synthesis: none;\">text</p>");
    }

    @Test
    void style_withFontSynthesisWeight_isAllowed() {
        assertThat(rule.apply("<p style=\"font-synthesis-weight: none;\">text</p>"))
                .isEqualTo("<p style=\"font-synthesis-weight: none;\">text</p>");
    }

    @Test
    void style_withFontSynthesisStyle_isAllowed() {
        assertThat(rule.apply("<p style=\"font-synthesis-style: none;\">text</p>"))
                .isEqualTo("<p style=\"font-synthesis-style: none;\">text</p>");
    }

    @Test
    void style_withFontSynthesisSmallCaps_isAllowed() {
        assertThat(rule.apply("<p style=\"font-synthesis-small-caps: none;\">text</p>"))
                .isEqualTo("<p style=\"font-synthesis-small-caps: none;\">text</p>");
    }

    @Test
    void style_withFontSynthesisPosition_isAllowed() {
        assertThat(rule.apply("<p style=\"font-synthesis-position: none;\">text</p>"))
                .isEqualTo("<p style=\"font-synthesis-position: none;\">text</p>");
    }

    @Test
    void style_withHangingPunctuation_isAllowed() {
        assertThat(rule.apply("<p style=\"hanging-punctuation: first;\">text</p>"))
                .isEqualTo("<p style=\"hanging-punctuation: first;\">text</p>");
    }

    @Test
    void style_withFontOpticalSizing_isAllowed() {
        assertThat(rule.apply("<p style=\"font-optical-sizing: auto;\">text</p>"))
                .isEqualTo("<p style=\"font-optical-sizing: auto;\">text</p>");
    }

    @Test
    void style_withFontKerning_isAllowed() {
        assertThat(rule.apply("<p style=\"font-kerning: normal;\">text</p>"))
                .isEqualTo("<p style=\"font-kerning: normal;\">text</p>");
    }

    @Test
    void style_withOrphansAndWidows_isAllowed() {
        assertThat(rule.apply("<p style=\"orphans: 2; widows: 2;\">text</p>"))
                .isEqualTo("<p style=\"orphans: 2; widows: 2;\">text</p>");
    }

    @Test
    void style_withScrollSnapType_isAllowed() {
        assertThat(rule.apply("<div style=\"scroll-snap-type: x mandatory;\">text</div>"))
                .isEqualTo("<div style=\"scroll-snap-type: x mandatory;\">text</div>");
    }

    @Test
    void style_withScrollSnapAlign_isAllowed() {
        assertThat(rule.apply("<div style=\"scroll-snap-align: start;\">text</div>"))
                .isEqualTo("<div style=\"scroll-snap-align: start;\">text</div>");
    }

    @Test
    void style_withOverscrollBehavior_isAllowed() {
        assertThat(rule.apply("<div style=\"overscroll-behavior: contain;\">text</div>"))
                .isEqualTo("<div style=\"overscroll-behavior: contain;\">text</div>");
    }

    @Test
    void style_withTextSizeAdjust_isAllowed() {
        assertThat(rule.apply("<p style=\"-webkit-text-size-adjust: 100%;\">text</p>"))
                .isEqualTo("<p style=\"-webkit-text-size-adjust: 100%;\">text</p>");
    }

    @Test
    void style_withColorScheme_isAllowed() {
        assertThat(rule.apply("<div style=\"color-scheme: light dark;\">text</div>"))
                .isEqualTo("<div style=\"color-scheme: light dark;\">text</div>");
    }

    @Test
    void style_withBreakInside_isAllowed() {
        assertThat(rule.apply("<div style=\"break-inside: avoid;\">text</div>"))
                .isEqualTo("<div style=\"break-inside: avoid;\">text</div>");
    }

    @Test
    void style_withPrintColorAdjust_isAllowed() {
        assertThat(rule.apply("<div style=\"print-color-adjust: exact;\">text</div>"))
                .isEqualTo("<div style=\"print-color-adjust: exact;\">text</div>");
    }

    @Test
    void style_withShapeOutside_isAllowed() {
        assertThat(rule.apply("<div style=\"float: left; shape-outside: circle(50%);\">text</div>"))
                .isEqualTo("<div style=\"float: left; shape-outside: circle(50%);\">text</div>");
    }

    @Test
    void style_withWillChange_isAllowed() {
        assertThat(rule.apply("<div style=\"will-change: transform;\">text</div>"))
                .isEqualTo("<div style=\"will-change: transform;\">text</div>");
    }

    @Test
    void style_withTextRendering_isAllowed() {
        assertThat(rule.apply("<p style=\"text-rendering: optimizeLegibility;\">text</p>"))
                .isEqualTo("<p style=\"text-rendering: optimizeLegibility;\">text</p>");
    }

    @Test
    void style_withWebkitFontSmoothing_isAllowed() {
        assertThat(rule.apply("<div style=\"-webkit-font-smoothing: antialiased;\">text</div>"))
                .isEqualTo("<div style=\"-webkit-font-smoothing: antialiased;\">text</div>");
    }

    @Test
    void style_withMozOsxFontSmoothing_isAllowed() {
        assertThat(rule.apply("<div style=\"-moz-osx-font-smoothing: grayscale;\">text</div>"))
                .isEqualTo("<div style=\"-moz-osx-font-smoothing: grayscale;\">text</div>");
    }

    @Test
    void style_withRotate_isAllowed() {
        assertThat(rule.apply("<div style=\"rotate: 45deg;\">text</div>"))
                .isEqualTo("<div style=\"rotate: 45deg;\">text</div>");
    }

    @Test
    void style_withScale_isAllowed() {
        assertThat(rule.apply("<div style=\"scale: 1.5;\">text</div>"))
                .isEqualTo("<div style=\"scale: 1.5;\">text</div>");
    }

    @Test
    void style_withTranslate_isAllowed() {
        assertThat(rule.apply("<div style=\"translate: 10px 20px;\">text</div>"))
                .isEqualTo("<div style=\"translate: 10px 20px;\">text</div>");
    }

    @Test
    void style_withFontVariantNumeric_isAllowed() {
        assertThat(rule.apply("<p style=\"font-variant-numeric: tabular-nums;\">text</p>"))
                .isEqualTo("<p style=\"font-variant-numeric: tabular-nums;\">text</p>");
    }

    @Test
    void style_withFontVariantCaps_isAllowed() {
        assertThat(rule.apply("<p style=\"font-variant-caps: small-caps;\">text</p>"))
                .isEqualTo("<p style=\"font-variant-caps: small-caps;\">text</p>");
    }

    @Test
    void style_withWebkitLineClamp_isAllowed() {
        assertThat(rule.apply("<div style=\"display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden;\">text</div>"))
                .isEqualTo("<div style=\"display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden;\">text</div>");
    }

    @Test
    void style_withLineClamp_isAllowed() {
        assertThat(rule.apply("<div style=\"line-clamp: 3;\">text</div>"))
                .isEqualTo("<div style=\"line-clamp: 3;\">text</div>");
    }

    @Test
    void style_withHyphens_isAllowed() {
        assertThat(rule.apply("<p style=\"hyphens: auto;\">text</p>"))
                .isEqualTo("<p style=\"hyphens: auto;\">text</p>");
    }

    @Test
    void style_withTabSize_isAllowed() {
        assertThat(rule.apply("<pre style=\"tab-size: 4;\">code</pre>"))
                .isEqualTo("<pre style=\"tab-size: 4;\">code</pre>");
    }

    @Test
    void style_withTextWrapBalance_isAllowed() {
        assertThat(rule.apply("<h2 style=\"text-wrap: balance;\">heading</h2>"))
                .isEqualTo("<h2 style=\"text-wrap: balance;\">heading</h2>");
    }

    @Test
    void style_withBackgroundOrigin_isAllowed() {
        assertThat(rule.apply("<div style=\"background-origin: content-box;\">text</div>"))
                .isEqualTo("<div style=\"background-origin: content-box;\">text</div>");
    }

    @Test
    void style_withFontFeatureSettings_isAllowed() {
        // Single-quoted style attribute so that the CSS "liga" value passes through without
        // double-escaping; the sanitizer normalizes the output to double-quoted attributes.
        assertThat(rule.apply("<p style='font-feature-settings: \"liga\" 1;'>text</p>"))
                .isEqualTo("<p style=\"font-feature-settings: &quot;liga&quot; 1;\">text</p>");
    }

    @Test
    void style_withCounterReset_isAllowed() {
        assertThat(rule.apply("<ol style=\"counter-reset: section;\"><li>item</li></ol>"))
                .isEqualTo("<ol style=\"counter-reset: section;\"><li>item</li></ol>");
    }

    @Test
    void style_withCounterIncrement_isAllowed() {
        assertThat(rule.apply("<li style=\"counter-increment: section;\">item</li>"))
                .isEqualTo("<li style=\"counter-increment: section;\">item</li>");
    }

    @Test
    void style_withGridTemplateColumns_isAllowed() {
        assertThat(rule.apply("<div style=\"display: grid; grid-template-columns: 1fr 1fr;\">content</div>"))
                .isEqualTo("<div style=\"display: grid; grid-template-columns: 1fr 1fr;\">content</div>");
    }

    // -------------------------------------------------------------------------
    // CSS custom properties (--*)
    // -------------------------------------------------------------------------

    @Test
    void style_withCustomProperty_isAllowed() {
        assertThat(rule.apply("<div style=\"--primary-color: #3498db;\">text</div>"))
                .isEqualTo("<div style=\"--primary-color: #3498db;\">text</div>");
    }

    @Test
    void style_withCustomProperty_preservesCase() {
        // CSS custom properties are case-sensitive — --MyColor and --mycolor are distinct.
        assertThat(rule.apply("<div style=\"--MyColor: red;\">text</div>"))
                .isEqualTo("<div style=\"--MyColor: red;\">text</div>");
    }

    @Test
    void style_withMultipleCustomProperties_areAllowed() {
        assertThat(rule.apply("<div style=\"--font-size: 16px; --line-height: 1.5;\">text</div>"))
                .isEqualTo("<div style=\"--font-size: 16px; --line-height: 1.5;\">text</div>");
    }

    @Test
    void style_withCustomProperty_dangerousValue_isRemoved() {
        assertThat(rule.apply("<div style=\"--bg: javascript:alert(1);\">text</div>"))
                .isEqualTo("<div>text</div>");
    }

    @Test
    void style_withCustomProperty_dangerousUrl_isRemoved() {
        assertThat(rule.apply("<div style=\"--img: url(javascript:alert(1));\">text</div>"))
                .isEqualTo("<div>text</div>");
    }

    @Test
    void style_withExpressionBypassViaCssComment_isRemoved() {
        // CSS comments are stripped before DANGEROUS_CSS_VALUE check to prevent
        // "exp/**/ression(alert(1))" from bypassing the expression() pattern
        assertThat(rule.apply("<span style=\"color: exp/**/ression(alert(1));\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withExpressionCommentAroundParen_isRemoved() {
        // Another variant: expression/**/( ) — comment between keyword and parenthesis
        assertThat(rule.apply("<span style=\"color: expression/**/(alert(1));\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withCssUnicodeEscapeBypass_isRemoved() {
        // \65 is the CSS unicode escape for 'e', so \65xpression decodes to "expression".
        // The sanitizer must decode CSS unicode escapes before pattern matching.
        assertThat(rule.apply("<span style=\"color: \\65xpression(alert(1));\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withCssNullByteBypass_isRemoved() {
        // A null byte between characters can break naive pattern matching.
        // The sanitizer strips null bytes before matching DANGEROUS_CSS_VALUE.
        assertThat(rule.apply("<span style=\"color: exp\u0000ression(alert(1));\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withUnicodeEscapeToNullByteBypass_isRemoved() {
        // \000000 decodes to codepoint 0 (null char) AFTER the initial null-byte strip.
        // The sanitizer re-strips null bytes after unicode decoding to catch this.
        assertThat(rule.apply("<span style=\"color: exp\\000000ression(alert(1));\">text</span>"))
                .isEqualTo("<span>text</span>");
    }

    @Test
    void style_withInvalidUnicodeCodepoint_doesNotThrow() {
        // \FFFFFF exceeds the valid Unicode range (U+10FFFF).
        // Character.toChars() would throw IllegalArgumentException — the sanitizer must
        // drop the escape gracefully. The resulting empty value ("color: ;") is invalid CSS
        // that browsers ignore, so there is no XSS risk.
        assertThat(rule.apply("<span style=\"color: \\FFFFFF;\">text</span>"))
                .isEqualTo("<span style=\"color: ;\">text</span>");
    }

    // -------------------------------------------------------------------------
    // lang / dir global attributes
    // -------------------------------------------------------------------------

    @Test
    void langAttribute_isAllowed() {
        assertThat(rule.apply("<p lang=\"ko\">Korean</p>")).isEqualTo("<p lang=\"ko\">Korean</p>");
    }

    @Test
    void dirAttribute_rtl_isAllowed() {
        assertThat(rule.apply("<p dir=\"rtl\">RTL text</p>")).isEqualTo("<p dir=\"rtl\">RTL text</p>");
    }

    @Test
    void langAndDir_onSpan_isAllowed() {
        assertThat(rule.apply("<span lang=\"ar\" dir=\"rtl\">Arabic text</span>"))
                .isEqualTo("<span lang=\"ar\" dir=\"rtl\">Arabic text</span>");
    }

    // -------------------------------------------------------------------------
    // class / id attributes
    // -------------------------------------------------------------------------

    @Test
    void classAttribute_isAllowed() {
        assertThat(rule.apply("<p class=\"intro\">text</p>")).isEqualTo("<p class=\"intro\">text</p>");
    }

    @Test
    void titleAttribute_isGlobal() {
        assertThat(rule.apply("<span title=\"description\">text</span>")).isEqualTo("<span title=\"description\">text</span>");
    }

    @Test
    void titleAttribute_onTableCell_isAllowed() {
        assertThat(rule.apply("<td title=\"cell description\">data</td>")).isEqualTo("<td title=\"cell description\">data</td>");
    }

    @Test
    void idAttribute_isAllowed() {
        assertThat(rule.apply("<p id=\"section1\">text</p>")).isEqualTo("<p id=\"section1\">text</p>");
    }

    @Test
    void idAttribute_onSpan_isAllowed() {
        assertThat(rule.apply("<span id=\"highlight\" class=\"red\">text</span>"))
                .isEqualTo("<span id=\"highlight\" class=\"red\">text</span>");
    }

    // -------------------------------------------------------------------------
    // mark / abbr / del / ins tags
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // kbd / var / samp / wbr / ruby tags
    // -------------------------------------------------------------------------

    @Test
    void kbdTag_passesThrough() {
        assertThat(rule.apply("<kbd>Ctrl+C</kbd>")).isEqualTo("<kbd>Ctrl+C</kbd>");
    }

    @Test
    void varTag_passesThrough() {
        assertThat(rule.apply("<var>x</var>")).isEqualTo("<var>x</var>");
    }

    @Test
    void sampTag_passesThrough() {
        assertThat(rule.apply("<samp>Hello World</samp>")).isEqualTo("<samp>Hello World</samp>");
    }

    @Test
    void wbrTag_passesThrough() {
        assertThat(rule.apply("very<wbr>long<wbr>word")).isEqualTo("very<wbr>long<wbr>word");
    }

    @Test
    void rubyTag_withRtAndRp_passesThrough() {
        assertThat(rule.apply("<ruby>kanji<rp>(</rp><rt>reading</rt><rp>)</rp></ruby>"))
                .isEqualTo("<ruby>kanji<rp>(</rp><rt>reading</rt><rp>)</rp></ruby>");
    }

    @Test
    void bdiTag_passesThrough() {
        assertThat(rule.apply("<p>Hello <bdi>username</bdi> World</p>"))
                .isEqualTo("<p>Hello <bdi>username</bdi> World</p>");
    }

    @Test
    void bdoTag_withDir_passesThrough() {
        assertThat(rule.apply("<bdo dir=\"rtl\">forced direction</bdo>"))
                .isEqualTo("<bdo dir=\"rtl\">forced direction</bdo>");
    }

    @Test
    void dfnTag_passesThrough() {
        assertThat(rule.apply("<dfn title=\"XSS\">Cross-Site Scripting</dfn>"))
                .isEqualTo("<dfn title=\"XSS\">Cross-Site Scripting</dfn>");
    }

    // -------------------------------------------------------------------------
    // picture / track / time tags
    // -------------------------------------------------------------------------

    @Test
    void pictureTag_passesThrough() {
        String input = "<picture><source media=\"(max-width: 600px)\" srcset=\"small.jpg\"><img src=\"fallback.jpg\" alt=\"photo\"></picture>";
        assertThat(rule.apply(input)).isEqualTo(input);
    }

    @Test
    void sourceInPicture_withDangerousSrcset_isDropped() {
        assertThat(rule.apply("<picture><source srcset=\"javascript:alert(1)\"><img src=\"/img.jpg\" alt=\"\"></picture>"))
                .isEqualTo("<picture><source><img src=\"/img.jpg\" alt=\"\"></picture>");
    }

    @Test
    void trackTag_withSafeAttributes_isAllowed() {
        assertThat(rule.apply("<track src=\"/en.vtt\" kind=\"subtitles\" srclang=\"en\" label=\"English\">"))
                .isEqualTo("<track src=\"/en.vtt\" kind=\"subtitles\" srclang=\"en\" label=\"English\">");
    }

    @Test
    void trackTag_withJavascriptSrc_isRemoved() {
        assertThat(rule.apply("<track src=\"javascript:alert(1)\" kind=\"subtitles\">"))
                .isEqualTo("<track kind=\"subtitles\">");
    }

    @Test
    void timeTag_withDatetime_isAllowed() {
        assertThat(rule.apply("<time datetime=\"2024-01-01\">January 1, 2024</time>"))
                .isEqualTo("<time datetime=\"2024-01-01\">January 1, 2024</time>");
    }

    // -------------------------------------------------------------------------
    // mark / abbr / del / ins tags
    // -------------------------------------------------------------------------

    @Test
    void markTag_passesThrough() {
        assertThat(rule.apply("<mark>highlighted</mark>")).isEqualTo("<mark>highlighted</mark>");
    }

    @Test
    void blockquoteCite_withSafeUrl_isAllowed() {
        assertThat(rule.apply("<blockquote cite=\"https://example.com/source\">quoted text</blockquote>"))
                .isEqualTo("<blockquote cite=\"https://example.com/source\">quoted text</blockquote>");
    }

    @Test
    void blockquoteCite_withJavascriptUrl_isRemoved() {
        assertThat(rule.apply("<blockquote cite=\"javascript:alert(1)\">quoted text</blockquote>"))
                .isEqualTo("<blockquote>quoted text</blockquote>");
    }

    @Test
    void qCite_withSafeUrl_isAllowed() {
        assertThat(rule.apply("<q cite=\"https://example.com\">quoted</q>"))
                .isEqualTo("<q cite=\"https://example.com\">quoted</q>");
    }

    @Test
    void abbrTag_withTitle_isAllowed() {
        assertThat(rule.apply("<abbr title=\"HyperText Markup Language\">HTML</abbr>"))
                .isEqualTo("<abbr title=\"HyperText Markup Language\">HTML</abbr>");
    }

    @Test
    void delTag_withDatetime_isAllowed() {
        assertThat(rule.apply("<del datetime=\"2024-01-01\">deleted</del>"))
                .isEqualTo("<del datetime=\"2024-01-01\">deleted</del>");
    }

    @Test
    void insTag_withDatetime_isAllowed() {
        assertThat(rule.apply("<ins datetime=\"2024-06-01\">inserted</ins>"))
                .isEqualTo("<ins datetime=\"2024-06-01\">inserted</ins>");
    }

    // -------------------------------------------------------------------------
    // video / audio / source tags
    // -------------------------------------------------------------------------

    @Test
    void videoPlaysinline_isAllowed() {
        assertThat(rule.apply("<video src=\"/movie.mp4\" playsinline></video>"))
                .isEqualTo("<video src=\"/movie.mp4\" playsinline=\"\"></video>");
    }

    @Test
    void videoTag_withSrcAndControls_isAllowed() {
        assertThat(rule.apply("<video src=\"/movie.mp4\" controls></video>"))
                .isEqualTo("<video src=\"/movie.mp4\" controls=\"\"></video>");
    }

    @Test
    void videoTag_withPoster_isAllowed() {
        assertThat(rule.apply("<video src=\"/movie.mp4\" poster=\"/thumb.jpg\"></video>"))
                .isEqualTo("<video src=\"/movie.mp4\" poster=\"/thumb.jpg\"></video>");
    }

    @Test
    void videoTag_withJavascriptPoster_isRemoved() {
        assertThat(rule.apply("<video poster=\"javascript:alert(1)\"></video>"))
                .isEqualTo("<video></video>");
    }

    @Test
    void videoTag_withJavascriptSrc_isRemoved() {
        assertThat(rule.apply("<video src=\"javascript:alert(1)\"></video>"))
                .isEqualTo("<video></video>");
    }

    @Test
    void audioTag_withSrcAndControls_isAllowed() {
        assertThat(rule.apply("<audio src=\"/song.mp3\" controls></audio>"))
                .isEqualTo("<audio src=\"/song.mp3\" controls=\"\"></audio>");
    }

    @Test
    void audioTag_onerrorAttribute_isRemoved() {
        assertThat(rule.apply("<audio src=\"/song.mp3\" onerror=\"alert(1)\"></audio>"))
                .isEqualTo("<audio src=\"/song.mp3\"></audio>");
    }

    @Test
    void videoPreload_isAllowed() {
        assertThat(rule.apply("<video src=\"/movie.mp4\" preload=\"none\"></video>"))
                .isEqualTo("<video src=\"/movie.mp4\" preload=\"none\"></video>");
    }

    @Test
    void audioPreload_isAllowed() {
        assertThat(rule.apply("<audio src=\"/song.mp3\" preload=\"metadata\"></audio>"))
                .isEqualTo("<audio src=\"/song.mp3\" preload=\"metadata\"></audio>");
    }

    @Test
    void sourceTag_withWidthAndHeight_isAllowed() {
        assertThat(rule.apply("<picture><source srcset=\"/img.webp\" width=\"800\" height=\"600\"><img src=\"/img.jpg\" alt=\"photo\"></picture>"))
                .isEqualTo("<picture><source srcset=\"/img.webp\" width=\"800\" height=\"600\"><img src=\"/img.jpg\" alt=\"photo\"></picture>");
    }

    @Test
    void sourceTag_withSrcAndType_isAllowed() {
        assertThat(rule.apply("<source src=\"/movie.webm\" type=\"video/webm\">"))
                .isEqualTo("<source src=\"/movie.webm\" type=\"video/webm\">");
    }

    @Test
    void sourceTag_withJavascriptSrc_isRemoved() {
        assertThat(rule.apply("<source src=\"javascript:alert(1)\">"))
                .isEqualTo("<source>");
    }

    // -------------------------------------------------------------------------
    // HTML injection in non-URL allowed attributes
    // -------------------------------------------------------------------------

    @Test
    void htmlInAltAttribute_isEscaped() {
        // alt is an allowed attribute on img — HTML inside it must be escaped, not executed
        assertThat(rule.apply("<img src=\"/img.png\" alt=\"<script>alert(1)</script>\">"))
                .isEqualTo("<img src=\"/img.png\" alt=\"&lt;script&gt;alert(1)&lt;/script&gt;\">");
    }

    @Test
    void htmlInTitleAttribute_isEscaped() {
        // title is an allowed attribute on a — HTML inside it must be escaped
        assertThat(rule.apply("<a href=\"/\" title=\"<b onmouseover=alert(1)>hover</b>\">link</a>"))
                .isEqualTo("<a href=\"/\" title=\"&lt;b onmouseover=alert(1)&gt;hover&lt;/b&gt;\">link</a>");
    }

    // -------------------------------------------------------------------------
    // Per-tag attributes
    // -------------------------------------------------------------------------

    @Test
    void anchorTargetBlank_relNoopenerNoreferrerAutoAdded() {
        // target="_blank" without rel → rel="noopener noreferrer" must be injected automatically
        assertThat(rule.apply("<a href=\"/\" target=\"_blank\">link</a>"))
                .isEqualTo("<a href=\"/\" target=\"_blank\" rel=\"noopener noreferrer\">link</a>");
    }

    @Test
    void anchorTargetBlank_existingRelPreserved_noopenerAppended() {
        // rel="nofollow" is preserved; noopener + noreferrer are appended
        assertThat(rule.apply("<a href=\"/\" target=\"_blank\" rel=\"nofollow\">link</a>"))
                .isEqualTo("<a href=\"/\" target=\"_blank\" rel=\"nofollow noopener noreferrer\">link</a>");
    }

    @Test
    void anchorTargetBlank_existingRelAlreadyComplete_notDuplicated() {
        // rel already has noopener + noreferrer → no duplicates
        assertThat(rule.apply("<a href=\"/\" target=\"_blank\" rel=\"noopener noreferrer\">link</a>"))
                .isEqualTo("<a href=\"/\" target=\"_blank\" rel=\"noopener noreferrer\">link</a>");
    }

    @Test
    void anchorTargetSelf_relNotModified() {
        // target="_self" is not _blank → rel is output as-is, no enforcement
        assertThat(rule.apply("<a href=\"/\" target=\"_self\" rel=\"nofollow\">link</a>"))
                .isEqualTo("<a href=\"/\" target=\"_self\" rel=\"nofollow\">link</a>");
    }

    @Test
    void anchorNoTarget_relOutputAsIs() {
        // No target → rel is output unchanged (existing behavior)
        assertThat(rule.apply("<a href=\"/\" rel=\"nofollow\">link</a>"))
                .isEqualTo("<a href=\"/\" rel=\"nofollow\">link</a>");
    }

    @Test
    void anchorReferrerpolicy_isAllowed() {
        assertThat(rule.apply("<a href=\"/\" referrerpolicy=\"no-referrer\">link</a>"))
                .isEqualTo("<a href=\"/\" referrerpolicy=\"no-referrer\">link</a>");
    }

    @Test
    void imgReferrerpolicy_isAllowed() {
        assertThat(rule.apply("<img src=\"/img.png\" referrerpolicy=\"no-referrer\">"))
                .isEqualTo("<img src=\"/img.png\" referrerpolicy=\"no-referrer\">");
    }

    @Test
    void anchorHreflang_isAllowed() {
        assertThat(rule.apply("<a href=\"/en\" hreflang=\"en\">English</a>"))
                .isEqualTo("<a href=\"/en\" hreflang=\"en\">English</a>");
    }

    @Test
    void anchorType_isAllowed() {
        assertThat(rule.apply("<a href=\"/file.pdf\" type=\"application/pdf\">Download</a>"))
                .isEqualTo("<a href=\"/file.pdf\" type=\"application/pdf\">Download</a>");
    }

    @Test
    void imgDecoding_isAllowed() {
        assertThat(rule.apply("<img src=\"/img.png\" decoding=\"async\">"))
                .isEqualTo("<img src=\"/img.png\" decoding=\"async\">");
    }

    @Test
    void imgFetchpriority_isAllowed() {
        assertThat(rule.apply("<img src=\"/hero.png\" fetchpriority=\"high\">"))
                .isEqualTo("<img src=\"/hero.png\" fetchpriority=\"high\">");
    }

    @Test
    void imgWidthAndHeight_areAllowed() {
        assertThat(rule.apply("<img src=\"/img.png\" width=\"100\" height=\"50\">"))
                .isEqualTo("<img src=\"/img.png\" width=\"100\" height=\"50\">");
    }

    @Test
    void imgSrcset_withSafeUrls_isAllowed() {
        assertThat(rule.apply("<img src=\"/img.png\" srcset=\"/img.png 1x, /img@2x.png 2x\">"))
                .isEqualTo("<img src=\"/img.png\" srcset=\"/img.png 1x, /img@2x.png 2x\">");
    }

    @Test
    void imgSrcset_withWidthDescriptor_isAllowed() {
        assertThat(rule.apply("<img src=\"/img.png\" srcset=\"/img-480.png 480w, /img-800.png 800w\">"))
                .isEqualTo("<img src=\"/img.png\" srcset=\"/img-480.png 480w, /img-800.png 800w\">");
    }

    @Test
    void imgSrcset_withDangerousUrl_dropsOnlyUnsafeEntry() {
        // Only the dangerous URL entry is removed; safe entries are preserved
        assertThat(rule.apply("<img srcset=\"/safe.png 1x, javascript:alert(1) 2x\">"))
                .isEqualTo("<img srcset=\"/safe.png 1x\">");
    }

    @Test
    void imgSrcset_withAllDangerousUrls_removesEntireSrcset() {
        assertThat(rule.apply("<img srcset=\"javascript:alert(1) 1x, data:text/html,<h1>xss</h1> 2x\">"))
                .isEqualTo("<img>");
    }

    @Test
    void imgSrcset_withHttpsUrl_isAllowed() {
        assertThat(rule.apply("<img srcset=\"https://cdn.example.com/img@2x.png 2x\">"))
                .isEqualTo("<img srcset=\"https://cdn.example.com/img@2x.png 2x\">");
    }

    @Test
    void imgSizes_isAllowed() {
        assertThat(rule.apply("<img src=\"/img.png\" sizes=\"(max-width: 600px) 480px, 800px\">"))
                .isEqualTo("<img src=\"/img.png\" sizes=\"(max-width: 600px) 480px, 800px\">");
    }

    @Test
    void imgCrossorigin_isAllowed() {
        assertThat(rule.apply("<img src=\"https://cdn.example.com/img.png\" crossorigin=\"anonymous\">"))
                .isEqualTo("<img src=\"https://cdn.example.com/img.png\" crossorigin=\"anonymous\">");
    }

    @Test
    void videoCrossorigin_isAllowed() {
        assertThat(rule.apply("<video src=\"/movie.mp4\" crossorigin=\"use-credentials\"></video>"))
                .isEqualTo("<video src=\"/movie.mp4\" crossorigin=\"use-credentials\"></video>");
    }

    @Test
    void audioCrossorigin_isAllowed() {
        assertThat(rule.apply("<audio src=\"/song.mp3\" crossorigin=\"anonymous\"></audio>"))
                .isEqualTo("<audio src=\"/song.mp3\" crossorigin=\"anonymous\"></audio>");
    }

    @Test
    void imgLoading_lazy_isAllowed() {
        assertThat(rule.apply("<img src=\"/img.png\" loading=\"lazy\">"))
                .isEqualTo("<img src=\"/img.png\" loading=\"lazy\">");
    }

    @Test
    void tdColspan_isAllowed() {
        assertThat(rule.apply("<td colspan=\"2\">cell</td>")).isEqualTo("<td colspan=\"2\">cell</td>");
    }

    @Test
    void colWidth_isAllowed() {
        assertThat(rule.apply("<colgroup><col width=\"100\"><col width=\"200\"></colgroup>"))
                .isEqualTo("<colgroup><col width=\"100\"><col width=\"200\"></colgroup>");
    }

    @Test
    void thAbbr_isAllowed() {
        assertThat(rule.apply("<th abbr=\"Name\">Full Name</th>"))
                .isEqualTo("<th abbr=\"Name\">Full Name</th>");
    }

    @Test
    void thScope_isAllowed() {
        assertThat(rule.apply("<th scope=\"col\">Name</th>")).isEqualTo("<th scope=\"col\">Name</th>");
    }

    @Test
    void tdAlign_isAllowed() {
        assertThat(rule.apply("<td align=\"center\" valign=\"top\">cell</td>"))
                .isEqualTo("<td align=\"center\" valign=\"top\">cell</td>");
    }

    @Test
    void thAlign_isAllowed() {
        assertThat(rule.apply("<th align=\"right\" valign=\"middle\">header</th>"))
                .isEqualTo("<th align=\"right\" valign=\"middle\">header</th>");
    }

    @Test
    void olReversed_isAllowed() {
        assertThat(rule.apply("<ol reversed><li>item</li></ol>"))
                .isEqualTo("<ol reversed=\"\"><li>item</li></ol>");
    }

    @Test
    void olStart_isAllowed() {
        assertThat(rule.apply("<ol start=\"5\"><li>item</li></ol>"))
                .isEqualTo("<ol start=\"5\"><li>item</li></ol>");
    }

    @Test
    void olType_isAllowed() {
        assertThat(rule.apply("<ol type=\"A\"><li>item</li></ol>"))
                .isEqualTo("<ol type=\"A\"><li>item</li></ol>");
    }

    @Test
    void liValue_isAllowed() {
        assertThat(rule.apply("<ol><li value=\"3\">third</li></ol>"))
                .isEqualTo("<ol><li value=\"3\">third</li></ol>");
    }

    // -------------------------------------------------------------------------
    // Common XSS attack vectors
    // -------------------------------------------------------------------------

    @Test
    void xssViaImgOnerror() {
        assertThat(rule.apply("<img src=x onerror=alert(1)>"))
                .isEqualTo("<img src=\"x\">");
    }

    @Test
    void xssViaSvgOnload() {
        assertThat(rule.apply("<svg onload=alert(1)>"))
                .isEqualTo("&lt;svg onload=alert(1)&gt;");
    }

    @Test
    void xssViaBodyOnload() {
        assertThat(rule.apply("<body onload=alert(1)>"))
                .isEqualTo("&lt;body onload=alert(1)&gt;");
    }

    @Test
    void xssViaUpperCaseScriptTag() {
        assertThat(rule.apply("<SCRIPT>alert(1)</SCRIPT>"))
                .isEqualTo("&lt;SCRIPT&gt;alert(1)&lt;&#x2F;SCRIPT&gt;");
    }

    @Test
    void xssViaScriptInAllowedTag() {
        // <script> nested inside allowed <p> must still be escaped
        assertThat(rule.apply("<p><script>alert(1)</script></p>"))
                .isEqualTo("<p>&lt;script&gt;alert(1)&lt;&#x2F;script&gt;</p>");
    }

    // -------------------------------------------------------------------------
    // Customization: add / remove allowed tags
    // -------------------------------------------------------------------------

    @Test
    void addAllowedTag_allowsNewTag() {
        // "video" is already in DEFAULT_ALLOWED_TAGS; adding it again has no effect.
        // src is in ALLOWED_ATTRIBUTES for video, so it passes through.
        WhitelistXssFilterRule custom = ruleWithAddTag("video");
        assertThat(custom.apply("<video src=\"/video.mp4\"></video>"))
                .isEqualTo("<video src=\"/video.mp4\"></video>");
    }

    @Test
    void removeAllowedTag_escapesRemovedTag() {
        WhitelistXssFilterRule custom = ruleWithRemoveTag("strike");
        assertThat(custom.apply("<strike>text</strike>"))
                .isEqualTo("&lt;strike&gt;text&lt;&#x2F;strike&gt;");
    }

    @Test
    void removeAllowedTag_doesNotAffectOtherTags() {
        WhitelistXssFilterRule custom = ruleWithRemoveTag("strike");
        assertThat(custom.apply("<b>bold</b>")).isEqualTo("<b>bold</b>");
    }

    // -------------------------------------------------------------------------
    // Customization: add / remove CSS properties
    // -------------------------------------------------------------------------

    @Test
    void addAllowedCssProperty_allowsNewProperty() {
        WhitelistXssFilterRule custom = ruleWithAddCss("position");
        assertThat(custom.apply("<div style=\"position: relative;\">text</div>"))
                .isEqualTo("<div style=\"position: relative;\">text</div>");
    }

    @Test
    void removeAllowedCssProperty_removesProperty() {
        WhitelistXssFilterRule custom = ruleWithRemoveCss("float");
        assertThat(custom.apply("<div style=\"float: left;\">text</div>"))
                .isEqualTo("<div>text</div>");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private WhitelistXssFilterRule ruleWithAddTag(String... tags) {
        Set<String> add = new HashSet<>();
        Collections.addAll(add, tags);
        return new WhitelistXssFilterRule(add, Collections.emptySet(), Collections.emptySet(), Collections.emptySet());
    }

    private WhitelistXssFilterRule ruleWithRemoveTag(String... tags) {
        Set<String> remove = new HashSet<>();
        Collections.addAll(remove, tags);
        return new WhitelistXssFilterRule(Collections.emptySet(), remove, Collections.emptySet(), Collections.emptySet());
    }

    private WhitelistXssFilterRule ruleWithAddCss(String... props) {
        Set<String> add = new HashSet<>();
        Collections.addAll(add, props);
        return new WhitelistXssFilterRule(Collections.emptySet(), Collections.emptySet(), add, Collections.emptySet());
    }

    private WhitelistXssFilterRule ruleWithRemoveCss(String... props) {
        Set<String> remove = new HashSet<>();
        Collections.addAll(remove, props);
        return new WhitelistXssFilterRule(Collections.emptySet(), Collections.emptySet(), Collections.emptySet(), remove);
    }
}
