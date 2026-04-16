package io.oakdom.xss.rule;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * XSS filter rule that permits a predefined set of safe HTML tags and per-tag safe
 * attributes, while escaping everything else.
 *
 * <h3>Allowed tags</h3>
 * <p>Inline: {@code b}, {@code i}, {@code em}, {@code strong}, {@code u}, {@code s},
 * {@code strike}, {@code small}, {@code sub}, {@code sup}, {@code cite}, {@code q},
 * {@code code}, {@code span}.
 *
 * <p>Block: {@code p}, {@code div}, {@code h1}–{@code h6}, {@code blockquote},
 * {@code pre}, {@code ul}, {@code ol}, {@code li}, {@code dl}, {@code dt}, {@code dd}.
 *
 * <p>Media: {@code a}, {@code img}, {@code figure}, {@code figcaption}.
 *
 * <p>Table: {@code table}, {@code thead}, {@code tbody}, {@code tfoot}, {@code tr},
 * {@code th}, {@code td}, {@code caption}, {@code col}, {@code colgroup}.
 *
 * <p>Other: {@code br}, {@code hr}.
 *
 * <h3>Allowed attributes</h3>
 * <p>The following attributes are permitted on every allowed tag:
 * <ul>
 *   <li>{@code class} — safe; only references CSS class names.</li>
 *   <li>{@code style} — permitted but sanitized. Only safe CSS properties are kept;
 *       dangerous patterns such as {@code expression()}, {@code javascript:}, and
 *       {@code behavior:} are removed. {@code url()} values are validated against
 *       the same URL allowlist used for {@code href} and {@code src}.</li>
 * </ul>
 *
 * <p>Tags with additional permitted attributes:
 * <ul>
 *   <li>{@code <a>} — {@code href}, {@code target}, {@code rel}, {@code title}.
 *       {@code href} accepts only {@code https://}, {@code http://}, {@code //},
 *       {@code /}, {@code #}, and scheme-less relative URLs.</li>
 *   <li>{@code <img>} — {@code src}, {@code alt}, {@code width}, {@code height},
 *       {@code title}. The same URL allowlist is applied to {@code src}.</li>
 *   <li>{@code <th>}, {@code <td>} — {@code colspan}, {@code rowspan}.</li>
 *   <li>{@code <col>}, {@code <colgroup>} — {@code span}.</li>
 * </ul>
 *
 * <p>Any tag not in the allowed list, along with all non-tag content, is escaped using
 * the same rules as {@link BlacklistXssFilterRule}: {@code &}, {@code <}, {@code >},
 * {@code "}, {@code '}, {@code /}, and {@code `}.
 *
 * <p>This rule is applied when the active {@link io.oakdom.core.filter.FilterMode} is
 * {@code WHITELIST}.
 */
public class WhitelistXssFilterRule implements XssFilterRule {

    /**
     * HTML tags that are permitted to pass through.
     * Tags absent from {@link #ALLOWED_ATTRIBUTES} may still carry
     * {@link #GLOBAL_ALLOWED_ATTRIBUTES}.
     */
    static final Set<String> ALLOWED_TAGS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            // inline
            "b", "i", "em", "strong", "u", "s", "strike", "small", "sub", "sup",
            "cite", "q", "code", "span",
            // block
            "p", "div", "h1", "h2", "h3", "h4", "h5", "h6",
            "blockquote", "pre", "ul", "ol", "li", "dl", "dt", "dd",
            // media
            "a", "img", "figure", "figcaption",
            // table
            "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "col", "colgroup",
            // other
            "br", "hr"
    )));

    /**
     * Attributes permitted on every allowed tag regardless of tag name.
     *
     * <p>{@code class} is safe as it only references CSS class names.
     * {@code style} is included but its value is sanitized by {@link #sanitizeCss(String)}
     * before being written to the output.
     */
    static final Set<String> GLOBAL_ALLOWED_ATTRIBUTES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("class", "style")));

    /**
     * Per-tag allowed attribute names, in addition to {@link #GLOBAL_ALLOWED_ATTRIBUTES}.
     */
    static final Map<String, Set<String>> ALLOWED_ATTRIBUTES;

    static {
        Map<String, Set<String>> map = new HashMap<>();
        map.put("a",         Collections.unmodifiableSet(new HashSet<>(Arrays.asList("href", "target", "rel", "title"))));
        map.put("img",       Collections.unmodifiableSet(new HashSet<>(Arrays.asList("src", "alt", "width", "height", "title"))));
        map.put("th",        Collections.unmodifiableSet(new HashSet<>(Arrays.asList("colspan", "rowspan"))));
        map.put("td",        Collections.unmodifiableSet(new HashSet<>(Arrays.asList("colspan", "rowspan"))));
        map.put("col",       Collections.unmodifiableSet(new HashSet<>(Collections.singletonList("span"))));
        map.put("colgroup",  Collections.unmodifiableSet(new HashSet<>(Collections.singletonList("span"))));
        ALLOWED_ATTRIBUTES = Collections.unmodifiableMap(map);
    }

    /**
     * Attribute names whose values must pass URL safety validation before being allowed.
     */
    private static final Set<String> URL_ATTRIBUTES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("href", "src")));

    /**
     * CSS properties that are safe to allow in {@code style} attributes.
     *
     * <p>{@code background} and {@code background-image} are included because they may
     * reference image URLs in editor-generated content. Their {@code url()} values are
     * individually validated by {@link #isSafeUrl(String)} before being accepted.
     */
    private static final Set<String> ALLOWED_CSS_PROPERTIES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "color", "background-color", "background", "background-image",
            "font", "font-size", "font-weight", "font-style", "font-family", "font-variant",
            "text-align", "text-decoration", "text-transform", "text-indent",
            "line-height", "letter-spacing", "word-spacing", "white-space",
            "margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
            "padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
            "border", "border-top", "border-right", "border-bottom", "border-left",
            "border-color", "border-width", "border-style", "border-radius",
            "width", "height", "max-width", "max-height", "min-width", "min-height",
            "display", "visibility", "opacity", "float", "clear", "vertical-align"
    )));

    /**
     * Matches an HTML opening or closing tag, capturing the optional closing slash,
     * the tag name, and any attribute string.
     */
    private static final Pattern TAG_PATTERN = Pattern.compile(
            "<(/?)([a-zA-Z][a-zA-Z0-9]*)(\\s[^>]*)?/?>",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Matches a single HTML attribute, capturing the name and value (double-quoted,
     * single-quoted, or unquoted).
     */
    private static final Pattern ATTR_PATTERN = Pattern.compile(
            "([a-zA-Z][a-zA-Z0-9-]*)\\s*(?:=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]*)))?",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Matches a single CSS declaration ({@code property: value}).
     */
    private static final Pattern CSS_PROPERTY_PATTERN = Pattern.compile(
            "([a-zA-Z-]+)\\s*:\\s*([^;]+)",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Matches known dangerous CSS value patterns that can execute scripts.
     *
     * <p>{@code url()} is intentionally excluded from this pattern; instead, the URL
     * inside {@code url()} is extracted and validated individually by
     * {@link #isSafeUrl(String)}.
     */
    private static final Pattern DANGEROUS_CSS_VALUE = Pattern.compile(
            "expression\\s*\\(|javascript\\s*:|vbscript\\s*:|behavior\\s*:|-moz-binding|@import",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Extracts the URL value from a CSS {@code url()} function.
     * Supports double-quoted, single-quoted, and unquoted URL values.
     */
    private static final Pattern CSS_URL_PATTERN = Pattern.compile(
            "url\\s*\\(\\s*['\"]?([^'\"\\)\\s]+)['\"]?\\s*\\)",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Applies the whitelist rule to the given value.
     *
     * <p>Allowed tags are preserved with only their permitted attributes. All other tags
     * and HTML-significant characters in non-tag content are escaped.
     *
     * @param value the raw input value; may be {@code null}
     * @return the sanitized value, or {@code null} if {@code value} is {@code null}
     */
    @Override
    public String apply(String value) {
        if (value == null) {
            return null;
        }

        StringBuilder result = new StringBuilder(value.length());
        Matcher matcher = TAG_PATTERN.matcher(value);
        int lastEnd = 0;

        while (matcher.find()) {
            result.append(escapeHtml(value.substring(lastEnd, matcher.start())));

            String closing = matcher.group(1);
            String tagName = matcher.group(2).toLowerCase();
            String attributes = matcher.group(3);

            if (ALLOWED_TAGS.contains(tagName)) {
                if (closing.isEmpty()) {
                    String safeAttrs = buildSafeAttributes(tagName, attributes);
                    result.append('<').append(tagName).append(safeAttrs).append('>');
                } else {
                    result.append("</").append(tagName).append('>');
                }
            } else {
                result.append(escapeHtml(matcher.group(0)));
            }

            lastEnd = matcher.end();
        }

        result.append(escapeHtml(value.substring(lastEnd)));

        return result.toString();
    }

    /**
     * Builds a safe attribute string for the given tag by retaining only allowed
     * attributes, rejecting unsafe URL values, and sanitizing {@code style} values.
     *
     * @param tagName    the lowercase tag name
     * @param attributes the raw attribute string from the matched tag, or {@code null}
     * @return a safe attribute string (may be empty), ready to append after the tag name
     */
    private String buildSafeAttributes(String tagName, String attributes) {
        if (attributes == null || attributes.trim().isEmpty()) {
            return "";
        }

        Set<String> allowedAttrs = ALLOWED_ATTRIBUTES.get(tagName);
        StringBuilder safeAttrs = new StringBuilder();
        Matcher attrMatcher = ATTR_PATTERN.matcher(attributes);

        while (attrMatcher.find()) {
            String attrName = attrMatcher.group(1).toLowerCase();
            if (!GLOBAL_ALLOWED_ATTRIBUTES.contains(attrName)
                    && (allowedAttrs == null || !allowedAttrs.contains(attrName))) {
                continue;
            }

            String attrValue = attrMatcher.group(2) != null ? attrMatcher.group(2)
                    : attrMatcher.group(3) != null ? attrMatcher.group(3)
                    : attrMatcher.group(4) != null ? attrMatcher.group(4)
                    : "";

            if (URL_ATTRIBUTES.contains(attrName)) {
                if (!isSafeUrl(attrValue)) {
                    continue;
                }
                safeAttrs.append(' ').append(attrName).append("=\"")
                        .append(escapeHtml(attrValue)).append('"');
            } else if ("style".equals(attrName)) {
                String safeCss = sanitizeCss(attrValue);
                if (!safeCss.isEmpty()) {
                    safeAttrs.append(' ').append("style").append("=\"")
                            .append(escapeHtml(safeCss)).append('"');
                }
            } else {
                safeAttrs.append(' ').append(attrName).append("=\"")
                        .append(escapeHtml(attrValue)).append('"');
            }
        }

        return safeAttrs.toString();
    }

    /**
     * Sanitizes a CSS {@code style} attribute value by allowing only properties in
     * {@link #ALLOWED_CSS_PROPERTIES} whose values are free of dangerous patterns.
     *
     * <p>Each CSS declaration is parsed individually. A declaration is dropped if:
     * <ul>
     *   <li>its property name is not in {@link #ALLOWED_CSS_PROPERTIES};</li>
     *   <li>its value matches {@link #DANGEROUS_CSS_VALUE}; or</li>
     *   <li>it contains a {@code url()} whose extracted URL does not pass
     *       {@link #isSafeUrl(String)}.</li>
     * </ul>
     *
     * @param style the raw {@code style} attribute value
     * @return a sanitized CSS string containing only safe declarations; never {@code null}
     */
    private String sanitizeCss(String style) {
        if (style == null || style.trim().isEmpty()) {
            return "";
        }

        StringBuilder safe = new StringBuilder();
        Matcher matcher = CSS_PROPERTY_PATTERN.matcher(style);

        while (matcher.find()) {
            String property = matcher.group(1).trim().toLowerCase();
            String cssValue = matcher.group(2).trim();

            if (!ALLOWED_CSS_PROPERTIES.contains(property)) {
                continue;
            }
            if (DANGEROUS_CSS_VALUE.matcher(cssValue).find()) {
                continue;
            }

            boolean hasUnsafeUrl = false;
            Matcher urlMatcher = CSS_URL_PATTERN.matcher(cssValue);
            while (urlMatcher.find()) {
                if (!isSafeUrl(urlMatcher.group(1))) {
                    hasUnsafeUrl = true;
                    break;
                }
            }
            if (hasUnsafeUrl) {
                continue;
            }

            if (safe.length() > 0) {
                safe.append(' ');
            }
            safe.append(property).append(": ").append(cssValue).append(';');
        }

        return safe.toString();
    }

    /**
     * Returns {@code true} if the given URL value is safe to use in an HTML attribute.
     *
     * <p>Only the following URL forms are permitted (allowlist approach):
     * <ul>
     *   <li>{@code https://} — absolute HTTPS URL</li>
     *   <li>{@code http://} — absolute HTTP URL</li>
     *   <li>{@code //} — protocol-relative URL</li>
     *   <li>{@code /} — absolute path</li>
     *   <li>{@code #} — fragment (anchor)</li>
     *   <li>No scheme (relative URL not containing {@code :}) — relative path</li>
     * </ul>
     *
     * <p>All other values, including {@code javascript:}, {@code vbscript:},
     * {@code data:}, and any encoding-based variants, are rejected.
     *
     * @param url the raw URL value to validate
     * @return {@code true} if the URL is safe; {@code false} otherwise
     */
    private boolean isSafeUrl(String url) {
        String trimmed = url.trim().toLowerCase();
        return trimmed.startsWith("https://")
                || trimmed.startsWith("http://")
                || trimmed.startsWith("//")
                || trimmed.startsWith("/")
                || trimmed.startsWith("#")
                || !trimmed.contains(":");
    }

    /**
     * Escapes all HTML-significant characters in a plain-text segment.
     *
     * @param text the text segment to escape
     * @return the escaped text
     */
    private String escapeHtml(String text) {
        return text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;")
                .replace("`", "&#x60;");
    }
}
