package io.oakdom.xss.processor;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.oakdom.core.filter.FilterMode;
import io.oakdom.xss.annotation.OakdomXssExclude;
import io.oakdom.xss.annotation.OakdomXssFilterMode;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies DTO field-level annotation support in {@link OakdomXssJsonRequestProcessor}.
 */
class OakdomXssJsonRequestProcessorDtoTest {

    private static final String XSS = "<script>alert(1)</script>";
    private static final String ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;";

    private final OakdomXssJsonRequestProcessor processor = new OakdomXssJsonRequestProcessor();

    // =========================================================================
    // Flat DTO
    // =========================================================================

    static class FlatDto {
        @OakdomXssExclude
        public String rawContent;

        @OakdomXssFilterMode(FilterMode.WHITELIST)
        public String htmlBody;

        public String title;
    }

    @Test
    void flatDto_excludedField_passesRaw() throws Exception {
        String json = "{\"rawContent\":\"" + XSS + "\",\"title\":\"hi\"}";
        String result = processor.process(json, FilterMode.BLACKLIST, FlatDto.class);
        assertTrue(result.contains(XSS), "excluded field must not be sanitized");
        assertTrue(result.contains("hi"), "non-annotated field must be present");
    }

    @Test
    void flatDto_nonAnnotatedField_usesBaseMode() throws Exception {
        String json = "{\"rawContent\":\"safe\",\"title\":\"" + XSS + "\"}";
        String result = processor.process(json, FilterMode.BLACKLIST, FlatDto.class);
        assertTrue(result.contains(ESCAPED), "non-annotated field must use base BLACKLIST mode");
        assertFalse(result.contains("<script>"), "non-annotated field must be sanitized");
    }

    @Test
    void flatDto_nullDtoClass_behavesLikeNoDto() throws Exception {
        String json = "{\"title\":\"" + XSS + "\"}";
        String withDto = processor.process(json, FilterMode.BLACKLIST, FlatDto.class);
        String withoutDto = processor.process(json, FilterMode.BLACKLIST, null);
        assertEquals(withoutDto, withDto,
                "null dtoClass must produce same result as no-dto processing for non-annotated field");
    }

    // =========================================================================
    // @JsonAlias name mapping
    // =========================================================================

    static class JsonAliasDto {
        @JsonAlias({"raw_content", "content_raw"})
        @OakdomXssExclude
        public String rawContent;

        @JsonAlias("html_body")
        @OakdomXssFilterMode(FilterMode.WHITELIST)
        public String htmlBody;
    }

    @Test
    void jsonAlias_excludedField_resolvedByAlias() throws Exception {
        // JSON key is an alias — excluded field must still pass through
        String json = "{\"raw_content\":\"" + XSS + "\"}";
        String result = processor.process(json, FilterMode.BLACKLIST, JsonAliasDto.class);
        assertTrue(result.contains(XSS), "@JsonAlias-mapped excluded field must not be sanitized");
    }

    @Test
    void jsonAlias_excludedField_resolvedBySecondAlias() throws Exception {
        // Second alias in the array must also resolve correctly
        String json = "{\"content_raw\":\"" + XSS + "\"}";
        String result = processor.process(json, FilterMode.BLACKLIST, JsonAliasDto.class);
        assertTrue(result.contains(XSS), "second @JsonAlias value must also resolve the excluded field");
    }

    @Test
    void jsonAlias_filterModeField_resolvedByAlias() throws Exception {
        // JSON key is an alias — field-level WHITELIST must apply (preserves <b>, base is BLACKLIST)
        String json = "{\"html_body\":\"<b>bold</b>\"}";
        String result = processor.process(json, FilterMode.BLACKLIST, JsonAliasDto.class);
        assertTrue(result.contains("<b>bold</b>"),
                "@JsonAlias-mapped WHITELIST field must preserve allowed tag <b>");
    }

    // =========================================================================
    // @JsonProperty name mapping
    // =========================================================================

    static class JsonPropertyDto {
        @JsonProperty("raw_content")
        @OakdomXssExclude
        public String rawContent;

        @JsonProperty("html_body")
        @OakdomXssFilterMode(FilterMode.WHITELIST)
        public String htmlBody;
    }

    @Test
    void jsonProperty_excludedField_resolvedByJsonName() throws Exception {
        String json = "{\"raw_content\":\"" + XSS + "\"}";
        String result = processor.process(json, FilterMode.BLACKLIST, JsonPropertyDto.class);
        assertTrue(result.contains(XSS), "@JsonProperty-mapped excluded field must not be sanitized");
    }

    // =========================================================================
    // Nested DTO
    // =========================================================================

    static class AuthorDto {
        @OakdomXssExclude
        public String bio;
        public String name;
    }

    static class PostDto {
        public String title;
        public AuthorDto author;
    }

    @Test
    void nestedDto_excludedField_passesRaw() throws Exception {
        String json = "{\"title\":\"" + XSS + "\","
                + "\"author\":{\"bio\":\"" + XSS + "\",\"name\":\"" + XSS + "\"}}";
        String result = processor.process(json, FilterMode.BLACKLIST, PostDto.class);

        // top-level title: sanitized
        assertTrue(result.contains(ESCAPED) || !result.contains("<script>alert(1)</script>\""),
                "title must be sanitized");
        // author.bio: excluded
        assertTrue(result.contains(XSS), "nested excluded field must pass through");
    }

    @Test
    void nestedDto_nonAnnotatedField_sanitized() throws Exception {
        String json = "{\"title\":\"safe\","
                + "\"author\":{\"bio\":\"safe\",\"name\":\"" + XSS + "\"}}";
        String result = processor.process(json, FilterMode.BLACKLIST, PostDto.class);
        assertFalse(result.contains("<script>"), "nested non-annotated field must be sanitized");
    }

    // =========================================================================
    // List<DTO>
    // =========================================================================

    static class CommentDto {
        @OakdomXssExclude
        public String rawText;
        public String author;
    }

    static class ArticleDto {
        public String title;
        public List<CommentDto> comments;
    }

    @Test
    void listOfDto_excludedFieldInElement_passesRaw() throws Exception {
        String json = "{\"title\":\"safe\","
                + "\"comments\":["
                + "{\"rawText\":\"" + XSS + "\",\"author\":\"" + XSS + "\"},"
                + "{\"rawText\":\"" + XSS + "\",\"author\":\"safe\"}"
                + "]}";
        String result = processor.process(json, FilterMode.BLACKLIST, ArticleDto.class);
        // rawText (excluded) must pass through — raw XSS appears in output
        assertTrue(result.contains("\"rawText\":\"" + XSS + "\""),
                "excluded field in List<DTO> element must pass through");
        // author (non-annotated) must be sanitized — raw XSS must NOT appear for author key
        assertTrue(result.contains("\"author\":\"" + ESCAPED + "\""),
                "non-annotated field in list element must be sanitized to escaped form");
    }

    // =========================================================================
    // List<String>
    // =========================================================================

    static class TagsDto {
        public List<String> tags;
    }

    @Test
    void listOfString_eachElementSanitized() throws Exception {
        String json = "{\"tags\":[\"" + XSS + "\",\"safe\"]}";
        String result = processor.process(json, FilterMode.BLACKLIST, TagsDto.class);
        assertFalse(result.contains("<script>"), "each string element in list must be sanitized");
        assertTrue(result.contains("safe"), "safe value must remain");
    }

    // =========================================================================
    // Map<String, String>
    // =========================================================================

    static class MetaDto {
        public Map<String, String> metadata;
    }

    @Test
    void mapOfString_valuesSanitized() throws Exception {
        String json = "{\"metadata\":{\"key\":\"" + XSS + "\"}}";
        String result = processor.process(json, FilterMode.BLACKLIST, MetaDto.class);
        assertFalse(result.contains("<script>"), "map string values must be sanitized");
    }

    // =========================================================================
    // Inheritance — superclass field annotation
    // =========================================================================

    static class BaseDto {
        @OakdomXssExclude
        public String superRaw;
    }

    static class ChildDto extends BaseDto {
        public String childField;
    }

    @Test
    void inheritance_superclassExcludedField_passesRaw() throws Exception {
        String json = "{\"superRaw\":\"" + XSS + "\",\"childField\":\"" + XSS + "\"}";
        String result = processor.process(json, FilterMode.BLACKLIST, ChildDto.class);
        assertTrue(result.contains(XSS), "inherited excluded field must pass through");
        // childField must be sanitized
        assertFalse(result.contains("\"childField\":\"" + XSS), "child non-annotated field must be sanitized");
    }

    // =========================================================================
    // Priority: DTO field annotation overrides base mode
    // =========================================================================

    static class PriorityDto {
        @OakdomXssFilterMode(FilterMode.BLACKLIST)
        public String alwaysBlacklist;
    }

    @Test
    void fieldAnnotation_overridesBaseModeWhitelist() throws Exception {
        // Base mode is WHITELIST → <b> would be preserved; field annotation forces BLACKLIST → <b> must be escaped.
        // Using <b> to distinguish: WHITELIST preserves allowed tags, BLACKLIST escapes them.
        String json = "{\"alwaysBlacklist\":\"<b>bold</b>\"}";
        String result = processor.process(json, FilterMode.WHITELIST, PriorityDto.class);
        assertTrue(result.contains("&lt;b&gt;bold&lt;/b&gt;"),
                "field-level BLACKLIST must override base WHITELIST mode — <b> must be escaped, not preserved");
    }

    // =========================================================================
    // No DTO class — existing behavior unchanged
    // =========================================================================

    @Test
    void noDtoClass_allStringsSanitized() throws Exception {
        String json = "{\"a\":\"" + XSS + "\",\"b\":\"safe\"}";
        String result = processor.process(json, FilterMode.BLACKLIST);
        assertFalse(result.contains("<script>"), "without dtoClass all strings must be sanitized");
        assertTrue(result.contains("safe"), "safe value must remain");
    }
}
