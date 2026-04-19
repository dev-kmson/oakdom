package io.oakdom.xss.processor;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.oakdom.core.filter.FilterMode;
import io.oakdom.core.resolver.ContentTypeResolver;
import io.oakdom.web.processor.OakdomRequestProcessor;
import io.oakdom.xss.annotation.OakdomXssExclude;
import io.oakdom.xss.annotation.OakdomXssFilterMode;
import io.oakdom.xss.sanitizer.DefaultXssSanitizer;
import io.oakdom.xss.sanitizer.XssSanitizer;

import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
 * <p>When a DTO class is provided via
 * {@link #process(String, FilterMode, Class)}, field-level
 * {@link OakdomXssExclude} and {@link OakdomXssFilterMode} annotations are
 * respected. Reflection metadata is cached per class so the cost is paid only
 * once across all requests for the same DTO type.
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

    /**
     * Per-class cache of JSON field name → {@link FieldInfo}.
     * Computed once on first use and reused across all subsequent requests.
     */
    private static final ConcurrentHashMap<Class<?>, Map<String, FieldInfo>> FIELD_CACHE =
            new ConcurrentHashMap<>();

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
        return process(value, filterMode, null);
    }

    /**
     * Parses the given JSON string and sanitizes all string values within it,
     * respecting field-level {@link OakdomXssExclude} and {@link OakdomXssFilterMode}
     * annotations declared on {@code dtoClass} and its nested types.
     *
     * <p>Field annotation metadata for {@code dtoClass} is computed once and cached
     * for the lifetime of the application; subsequent calls for the same class incur
     * no reflection overhead.
     *
     * <p>When {@code dtoClass} is {@code null}, behavior is identical to
     * {@link #process(String, FilterMode)}.
     *
     * @param value      the raw JSON string; may be {@code null}
     * @param filterMode the base filter mode; field annotations may override this per field
     * @param dtoClass   the target DTO class whose field annotations to apply; may be {@code null}
     * @return the sanitized JSON string, or {@code null} if {@code value} is {@code null}
     */
    public String process(String value, FilterMode filterMode, Class<?> dtoClass) {
        if (value == null) {
            return null;
        }
        if (value.trim().isEmpty()) {
            return value;
        }
        XssSanitizer sanitizer = selectSanitizer(filterMode);
        try {
            JsonNode root = MAPPER.readTree(value);
            JsonNode sanitized = sanitizeNodeWithDto(root, filterMode, dtoClass, null, 0);
            return MAPPER.writeValueAsString(sanitized);
        } catch (Exception e) {
            return sanitizer.sanitize(value);
        }
    }

    // -------------------------------------------------------------------------
    // DTO-aware recursive sanitization
    // -------------------------------------------------------------------------

    /**
     * Recursively sanitizes all string values in the given {@link JsonNode},
     * applying field-level annotations when {@code dtoClass} or {@code elementClass}
     * provides type context.
     *
     * @param node         the JSON node to sanitize
     * @param baseMode     the effective filter mode at this level
     * @param dtoClass     the Java class whose field map to consult for object nodes; may be {@code null}
     * @param elementClass the element/value type for array or map nodes; may be {@code null}
     * @param depth        the current recursion depth
     * @return the sanitized node
     */
    private JsonNode sanitizeNodeWithDto(JsonNode node, FilterMode baseMode,
                                         Class<?> dtoClass, Class<?> elementClass, int depth) {
        if (depth > MAX_DEPTH) {
            return node;
        }

        if (node.isTextual()) {
            return new TextNode(selectSanitizer(baseMode).sanitize(node.asText()));
        }

        if (node.isObject()) {
            ObjectNode result = MAPPER.createObjectNode();
            if (dtoClass != null && Map.class.isAssignableFrom(dtoClass)) {
                // Map field: sanitize each value using the map's value type
                Class<?> valueClass = isProcessableType(elementClass) ? elementClass : null;
                Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
                while (fields.hasNext()) {
                    Map.Entry<String, JsonNode> entry = fields.next();
                    result.set(entry.getKey(),
                            sanitizeNodeWithDto(entry.getValue(), baseMode, valueClass, null, depth + 1));
                }
            } else {
                Map<String, FieldInfo> fieldMap = dtoClass != null
                        ? getFieldMap(dtoClass)
                        : Collections.<String, FieldInfo>emptyMap();
                Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
                while (fields.hasNext()) {
                    Map.Entry<String, JsonNode> entry = fields.next();
                    result.set(entry.getKey(),
                            processFieldNode(entry.getValue(), baseMode, fieldMap.get(entry.getKey()), depth));
                }
            }
            return result;
        }

        if (node.isArray()) {
            ArrayNode result = MAPPER.createArrayNode();
            Class<?> elemDtoClass = isProcessableType(elementClass) ? elementClass : null;
            for (JsonNode element : node) {
                result.add(sanitizeNodeWithDto(element, baseMode, elemDtoClass, null, depth + 1));
            }
            return result;
        }

        return node;
    }

    /**
     * Applies the {@link FieldInfo} annotation settings to a single field's JSON node.
     *
     * @param fieldValue the JSON node for the field
     * @param baseMode   the inherited filter mode
     * @param info       the field annotation info; may be {@code null} if no annotation is present
     * @param depth      the current recursion depth
     * @return the processed node
     */
    private JsonNode processFieldNode(JsonNode fieldValue, FilterMode baseMode, FieldInfo info, int depth) {
        if (info == null) {
            return sanitizeNodeWithDto(fieldValue, baseMode, null, null, depth + 1);
        }
        if (info.excluded) {
            return fieldValue;
        }
        FilterMode effectiveMode = info.overrideMode != null ? info.overrideMode : baseMode;
        if (fieldValue.isObject()) {
            if (isMapType(info.fieldType)) {
                return sanitizeNodeWithDto(fieldValue, effectiveMode, info.fieldType, info.elementClass, depth + 1);
            }
            Class<?> nestedClass = isProcessableType(info.fieldType) ? info.fieldType : null;
            return sanitizeNodeWithDto(fieldValue, effectiveMode, nestedClass, null, depth + 1);
        }
        if (fieldValue.isArray()) {
            return sanitizeNodeWithDto(fieldValue, effectiveMode, null, info.elementClass, depth + 1);
        }
        return sanitizeNodeWithDto(fieldValue, effectiveMode, null, null, depth + 1);
    }

    // -------------------------------------------------------------------------
    // Field metadata cache
    // -------------------------------------------------------------------------

    private Map<String, FieldInfo> getFieldMap(Class<?> clazz) {
        return FIELD_CACHE.computeIfAbsent(clazz, OakdomXssJsonRequestProcessor::buildFieldMap);
    }

    /**
     * Builds a map of JSON field name → {@link FieldInfo} for the given class,
     * walking up the class hierarchy to include inherited fields.
     *
     * <p>Only fields that carry XSS annotations or whose type warrants recursive
     * processing are included; plain primitive and String fields without annotations
     * are omitted to keep the map lean.
     *
     * <p>{@link JsonAlias} values are registered under the same {@link FieldInfo}
     * as the primary name so that aliased JSON keys are resolved correctly.
     */
    private static Map<String, FieldInfo> buildFieldMap(Class<?> clazz) {
        Map<String, FieldInfo> map = new LinkedHashMap<>();
        Class<?> current = clazz;
        while (current != null && current != Object.class) {
            for (Field field : current.getDeclaredFields()) {
                String jsonName = resolveJsonName(field);
                if (map.containsKey(jsonName)) {
                    continue; // subclass field already registered
                }
                OakdomXssExclude exclude = field.getAnnotation(OakdomXssExclude.class);
                OakdomXssFilterMode modeAnnotation = field.getAnnotation(OakdomXssFilterMode.class);
                Class<?> fieldType = field.getType();
                Class<?> elementClass = resolveElementClass(field);

                boolean hasAnnotation = exclude != null || modeAnnotation != null;
                boolean hasNestedType = isProcessableType(fieldType) && !isCollectionOrMap(fieldType);
                boolean hasProcessableElement = elementClass != null && isProcessableType(elementClass);

                if (hasAnnotation || hasNestedType || hasProcessableElement) {
                    FieldInfo info = new FieldInfo(
                            exclude != null,
                            modeAnnotation != null ? modeAnnotation.value() : null,
                            fieldType,
                            elementClass
                    );
                    map.put(jsonName, info);
                    JsonAlias jsonAlias = field.getAnnotation(JsonAlias.class);
                    if (jsonAlias != null) {
                        for (String alias : jsonAlias.value()) {
                            if (!map.containsKey(alias)) {
                                map.put(alias, info);
                            }
                        }
                    }
                }
            }
            current = current.getSuperclass();
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * Resolves the JSON property name for a field, honoring {@link JsonProperty} if present.
     */
    private static String resolveJsonName(Field field) {
        JsonProperty jsonProperty = field.getAnnotation(JsonProperty.class);
        if (jsonProperty != null && !jsonProperty.value().isEmpty()) {
            return jsonProperty.value();
        }
        return field.getName();
    }

    /**
     * Resolves the element type for collection fields ({@code List<T>} → {@code T})
     * and the value type for map fields ({@code Map<K,V>} → {@code V}).
     * Returns {@code null} for non-generic or unsupported types.
     */
    private static Class<?> resolveElementClass(Field field) {
        Type genericType = field.getGenericType();
        if (!(genericType instanceof ParameterizedType)) {
            return null;
        }
        ParameterizedType pt = (ParameterizedType) genericType;
        Type rawType = pt.getRawType();
        if (!(rawType instanceof Class)) {
            return null;
        }
        Class<?> rawClass = (Class<?>) rawType;
        Type[] args = pt.getActualTypeArguments();
        if (Collection.class.isAssignableFrom(rawClass)) {
            if (args.length > 0 && args[0] instanceof Class) {
                return (Class<?>) args[0];
            }
        } else if (Map.class.isAssignableFrom(rawClass)) {
            if (args.length > 1 && args[1] instanceof Class) {
                return (Class<?>) args[1];
            }
        }
        return null;
    }

    /**
     * Returns {@code true} if the given class is a user-defined type worth
     * recursing into (i.e., not a primitive, wrapper, String, enum, or standard
     * Java type).
     */
    private static boolean isProcessableType(Class<?> clazz) {
        if (clazz == null) return false;
        if (clazz.isPrimitive()) return false;
        if (clazz == String.class) return false;
        if (clazz == Object.class) return false;
        if (clazz == Boolean.class || clazz == Character.class) return false;
        if (Number.class.isAssignableFrom(clazz)) return false;
        if (clazz.isEnum()) return false;
        if (clazz.getName().startsWith("java.") || clazz.getName().startsWith("javax.")) return false;
        return true;
    }

    private static boolean isCollectionOrMap(Class<?> clazz) {
        return Collection.class.isAssignableFrom(clazz) || Map.class.isAssignableFrom(clazz);
    }

    private static boolean isMapType(Class<?> clazz) {
        return clazz != null && Map.class.isAssignableFrom(clazz);
    }

    private XssSanitizer selectSanitizer(FilterMode mode) {
        return mode == FilterMode.WHITELIST ? whitelistSanitizer : blacklistSanitizer;
    }

    // -------------------------------------------------------------------------
    // Field annotation metadata holder
    // -------------------------------------------------------------------------

    /**
     * Cached annotation metadata for a single DTO field.
     */
    private static final class FieldInfo {

        /** Whether {@link OakdomXssExclude} is present on this field. */
        final boolean excluded;

        /**
         * The {@link FilterMode} from {@link OakdomXssFilterMode} if present;
         * {@code null} if the annotation is absent (base mode applies).
         */
        final FilterMode overrideMode;

        /** The declared type of the field. */
        final Class<?> fieldType;

        /**
         * For {@code List<T>} / {@code Set<T>}: the element type {@code T}.
         * For {@code Map<K,V>}: the value type {@code V}.
         * {@code null} for non-generic fields.
         */
        final Class<?> elementClass;

        FieldInfo(boolean excluded, FilterMode overrideMode, Class<?> fieldType, Class<?> elementClass) {
            this.excluded = excluded;
            this.overrideMode = overrideMode;
            this.fieldType = fieldType;
            this.elementClass = elementClass;
        }
    }
}
