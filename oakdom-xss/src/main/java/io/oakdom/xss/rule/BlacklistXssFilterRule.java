package io.oakdom.xss.rule;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * XSS filter rule that escapes HTML-significant characters.
 *
 * <h3>Default escape set</h3>
 * <p>The five core characters are always escaped by default:
 * <ul>
 *   <li>{@code &} &rarr; {@code &amp;} (escaped first to prevent double-escaping)</li>
 *   <li>{@code <} &rarr; {@code &lt;}</li>
 *   <li>{@code >} &rarr; {@code &gt;}</li>
 *   <li>{@code "} &rarr; {@code &quot;}</li>
 *   <li>{@code '} &rarr; {@code &#x27;}</li>
 * </ul>
 *
 * <h3>Customization</h3>
 * <p>Use {@link #BlacklistXssFilterRule(Set, Set)} to add or remove characters from the
 * escape set. Characters added beyond the defaults use pre-defined named entities when
 * available ({@code /} → {@code &#x2F;}, {@code `} → {@code &#x60;}), and numeric
 * entities ({@code &#xHH;}) for all other characters.
 *
 * <p>Removing any of the five core characters is permitted but strongly discouraged,
 * as it degrades XSS protection.
 *
 * <p>This rule is applied when the active {@link io.oakdom.core.filter.FilterMode} is
 * {@code BLACKLIST}.
 */
public class BlacklistXssFilterRule implements XssFilterRule {

    /**
     * The five core HTML escape characters used by default.
     * Insertion order is significant: {@code &} must come first to prevent double-escaping.
     */
    static final Map<Character, String> DEFAULT_ESCAPE_MAP;

    static {
        Map<Character, String> map = new LinkedHashMap<>();
        map.put('&',  "&amp;");
        map.put('<',  "&lt;");
        map.put('>',  "&gt;");
        map.put('"',  "&quot;");
        map.put('\'', "&#x27;");
        DEFAULT_ESCAPE_MAP = Collections.unmodifiableMap(map);
    }

    /**
     * Pre-defined HTML entities for characters that may be added beyond the five defaults.
     */
    private static final Map<Character, String> KNOWN_ESCAPE_ENTITIES;

    static {
        Map<Character, String> map = new HashMap<>();
        map.put('/', "&#x2F;");
        map.put('`', "&#x60;");
        KNOWN_ESCAPE_ENTITIES = Collections.unmodifiableMap(map);
    }

    private final Map<Character, String> escapeMap;

    /**
     * Creates a rule using the five default HTML escape characters.
     */
    public BlacklistXssFilterRule() {
        this.escapeMap = DEFAULT_ESCAPE_MAP;
    }

    /**
     * Creates a rule starting from the five default HTML escape characters and
     * applying the given additions and removals.
     *
     * <p>Additions are appended after the defaults in iteration order of {@code addChars}.
     * For common extra characters, pre-defined entities are used:
     * {@code /} → {@code &#x2F;}, {@code `} → {@code &#x60;}.
     * All other added characters use numeric entities ({@code &#xHH;}).
     *
     * @param addChars    characters to add to the escape set; may be {@code null} or empty
     * @param removeChars characters to remove from the escape set; may be {@code null} or empty
     */
    public BlacklistXssFilterRule(Set<Character> addChars, Set<Character> removeChars) {
        if ((addChars == null || addChars.isEmpty()) && (removeChars == null || removeChars.isEmpty())) {
            this.escapeMap = DEFAULT_ESCAPE_MAP;
            return;
        }
        Map<Character, String> map = new LinkedHashMap<>(DEFAULT_ESCAPE_MAP);
        if (removeChars != null) {
            for (Character c : removeChars) {
                map.remove(c);
            }
        }
        if (addChars != null) {
            for (Character c : addChars) {
                if (KNOWN_ESCAPE_ENTITIES.containsKey(c)) {
                    map.put(c, KNOWN_ESCAPE_ENTITIES.get(c));
                } else {
                    map.put(c, "&#x" + Integer.toHexString(c).toUpperCase() + ";");
                }
            }
        }
        this.escapeMap = Collections.unmodifiableMap(map);
    }

    /**
     * Escapes all characters in the configured escape set.
     *
     * @param value the raw input value; may be {@code null}
     * @return the escaped value, or {@code null} if {@code value} is {@code null}
     */
    @Override
    public String apply(String value) {
        if (value == null) {
            return null;
        }
        String result = value;
        for (Map.Entry<Character, String> entry : escapeMap.entrySet()) {
            result = result.replace(String.valueOf(entry.getKey()), entry.getValue());
        }
        return result;
    }
}
