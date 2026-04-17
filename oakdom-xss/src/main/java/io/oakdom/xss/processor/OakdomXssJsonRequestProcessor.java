package io.oakdom.xss.processor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.oakdom.core.filter.FilterMode;
import io.oakdom.core.resolver.ContentTypeResolver;
import io.oakdom.web.processor.OakdomRequestProcessor;
import io.oakdom.xss.sanitizer.DefaultXssSanitizer;
import io.oakdom.xss.sanitizer.XssSanitizer;

import java.util.Iterator;
import java.util.Map;

/**
 * {@link OakdomRequestProcessor} for {@code application/json} requests.
 *
 * <p>Parses the JSON request body and recursively sanitizes all string values
 * using the configured {@link XssSanitizer}. Non-string values (numbers, booleans,
 * nulls, nested objects and arrays) are preserved as-is; only the string leaf nodes
 * are sanitized.
 *
 * <p>If the input cannot be parsed as valid JSON, it is treated as a plain string
 * and sanitized directly.
 *
 * <p>The no-arg constructor uses the default (uncustomized) sanitizers. When XSS
 * configuration customizations are needed, use
 * {@link #OakdomXssJsonRequestProcessor(XssSanitizer, XssSanitizer)} and pass
 * sanitizers obtained from {@link DefaultXssSanitizer#of(FilterMode, io.oakdom.xss.config.XssConfig)}.
 *
 * <p>Example — given the following JSON input with {@link FilterMode#BLACKLIST}:
 * <pre>{@code
 * {
 *   "title": "Hello <script>alert(1)</script>",
 *   "count": 42,
 *   "tags": ["safe", "<img onerror='xss'>"]
 * }
 * }</pre>
 * The output would be:
 * <pre>{@code
 * {
 *   "title": "Hello &lt;script&gt;alert(1)&lt;/script&gt;",
 *   "count": 42,
 *   "tags": ["safe", "&lt;img onerror=&#x27;xss&#x27;&gt;"]
 * }
 * }</pre>
 */
public class OakdomXssJsonRequestProcessor implements OakdomRequestProcessor {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Maximum allowed JSON nesting depth. Inputs exceeding this depth are returned
     * unchanged to prevent {@link StackOverflowError} from pathologically nested input.
     */
    private static final int MAX_DEPTH = 100;

    private final XssSanitizer blacklistSanitizer;
    private final XssSanitizer whitelistSanitizer;

    /**
     * Creates a processor using the default (uncustomized) sanitizers.
     */
    public OakdomXssJsonRequestProcessor() {
        this(DefaultXssSanitizer.of(FilterMode.BLACKLIST), DefaultXssSanitizer.of(FilterMode.WHITELIST));
    }

    /**
     * Creates a processor using the given sanitizers.
     *
     * @param blacklistSanitizer sanitizer applied when the filter mode is {@link FilterMode#BLACKLIST}; must not be {@code null}
     * @param whitelistSanitizer sanitizer applied when the filter mode is {@link FilterMode#WHITELIST}; must not be {@code null}
     */
    public OakdomXssJsonRequestProcessor(XssSanitizer blacklistSanitizer, XssSanitizer whitelistSanitizer) {
        if (blacklistSanitizer == null) {
            throw new IllegalArgumentException("blacklistSanitizer must not be null");
        }
        if (whitelistSanitizer == null) {
            throw new IllegalArgumentException("whitelistSanitizer must not be null");
        }
        this.blacklistSanitizer = blacklistSanitizer;
        this.whitelistSanitizer = whitelistSanitizer;
    }

    /**
     * Returns {@code true} if the given content type represents JSON.
     *
     * @param contentType the {@code Content-Type} header value
     * @return {@code true} if this processor supports the content type
     */
    @Override
    public boolean supports(String contentType) {
        return ContentTypeResolver.isJson(contentType);
    }

    /**
     * Parses the given JSON string and sanitizes all string values within it.
     *
     * <p>The JSON structure (objects, arrays, nesting) is preserved. Only
     * string-type leaf values are passed through the configured sanitizer.
     * If parsing fails, the entire value is sanitized as a plain string.
     *
     * @param value      the raw JSON string; may be {@code null}
     * @param filterMode the filter mode to apply; must not be {@code null}
     * @return the sanitized JSON string, or {@code null} if {@code value} is {@code null}
     */
    @Override
    public String process(String value, FilterMode filterMode) {
        if (value == null) {
            return null;
        }
        if (value.trim().isEmpty()) {
            return value;
        }
        XssSanitizer sanitizer = filterMode == FilterMode.WHITELIST ? whitelistSanitizer : blacklistSanitizer;
        try {
            JsonNode root = MAPPER.readTree(value);
            JsonNode sanitized = sanitizeNode(root, sanitizer, 0);
            return MAPPER.writeValueAsString(sanitized);
        } catch (Exception e) {
            return sanitizer.sanitize(value);
        }
    }

    /**
     * Recursively sanitizes all string values in the given {@link JsonNode}.
     *
     * <p>String nodes are sanitized and replaced. Object and array nodes are
     * traversed recursively. All other node types are returned unchanged.
     *
     * <p>Recursion is limited to {@link #MAX_DEPTH} levels. Nodes beyond that
     * depth are returned unchanged to prevent {@link StackOverflowError} from
     * pathologically nested input.
     *
     * @param node      the JSON node to sanitize
     * @param sanitizer the sanitizer to apply to string values
     * @param depth     the current recursion depth
     * @return the sanitized node
     */
    private JsonNode sanitizeNode(JsonNode node, XssSanitizer sanitizer, int depth) {
        if (depth > MAX_DEPTH) {
            return node;
        }

        if (node.isTextual()) {
            return new TextNode(sanitizer.sanitize(node.asText()));
        }

        if (node.isObject()) {
            ObjectNode result = MAPPER.createObjectNode();
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                result.set(field.getKey(), sanitizeNode(field.getValue(), sanitizer, depth + 1));
            }
            return result;
        }

        if (node.isArray()) {
            ArrayNode result = MAPPER.createArrayNode();
            for (JsonNode element : node) {
                result.add(sanitizeNode(element, sanitizer, depth + 1));
            }
            return result;
        }

        return node;
    }
}
