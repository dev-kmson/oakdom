package io.oakdom.xss.rule;

/**
 * XSS filter rule that escapes all HTML-significant characters.
 *
 * <p>All characters that have special meaning in HTML are replaced with their
 * corresponding HTML entities, preventing any HTML or script injection:
 * <ul>
 *   <li>{@code &} &rarr; {@code &amp;}</li>
 *   <li>{@code <} &rarr; {@code &lt;}</li>
 *   <li>{@code >} &rarr; {@code &gt;}</li>
 *   <li>{@code "} &rarr; {@code &quot;}</li>
 *   <li>{@code '} &rarr; {@code &#x27;}</li>
 *   <li>{@code /} &rarr; {@code &#x2F;} (prevents closing tags such as {@code </script>})</li>
 *   <li>{@code `} &rarr; {@code &#x60;} (prevents attribute delimiter injection in legacy browsers)</li>
 * </ul>
 *
 * <p>{@code &} is replaced first to avoid double-escaping subsequent substitutions.
 *
 * <p>This rule is applied when the active {@link io.oakdom.core.filter.FilterMode} is
 * {@code BLACKLIST}.
 */
public class BlacklistXssFilterRule implements XssFilterRule {

    /**
     * Escapes all HTML-significant characters in the given value.
     *
     * @param value the raw input value; may be {@code null}
     * @return the escaped value, or {@code null} if {@code value} is {@code null}
     */
    @Override
    public String apply(String value) {
        if (value == null) {
            return null;
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;")
                .replace("`", "&#x60;");
    }
}
