package io.oakdom.xss.filter;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.xss.annotation.OakdomXssExclude;
import io.oakdom.xss.annotation.OakdomXssFilterMode;
import io.oakdom.xss.config.XssConfig;
import io.oakdom.xss.interceptor.OakdomXssRequestAttributes;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Filter-level integration tests verifying that DTO field-level annotations are applied
 * end-to-end through {@link OakdomXssFilter}, and that the priority order for JSON body
 * processing is correct:
 *
 * <ol>
 *   <li>DTO field annotation ({@code @OakdomXssExclude} / {@code @OakdomXssFilterMode})</li>
 *   <li>{@code @RequestBody} parameter annotation</li>
 *   <li>Method-level annotation</li>
 *   <li>Config URL-pattern rule</li>
 *   <li>Global filter mode</li>
 * </ol>
 */
class OakdomXssFilterDtoAnnotationTest {

    private static final String XSS     = "<script>alert(1)</script>";
    private static final String ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;";

    private static byte[] readAllBytes(InputStream in) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = in.read(chunk)) != -1) buf.write(chunk, 0, n);
        return buf.toByteArray();
    }

    // =========================================================================
    // Test DTOs
    // =========================================================================

    static class ArticleDto {
        @OakdomXssExclude
        public String rawContent;

        @OakdomXssFilterMode(FilterMode.WHITELIST)
        public String htmlBody;

        public String title;
    }

    static class AuthorDto {
        @OakdomXssExclude
        public String bio;
        public String name;
    }

    static class PostDto {
        public String title;
        public AuthorDto author;
    }

    static class TagsDto {
        public List<String> tags;
    }

    static class PriorityDto {
        @OakdomXssFilterMode(FilterMode.BLACKLIST)
        public String alwaysBlacklist;

        @OakdomXssExclude
        public String rawField;
    }

    // =========================================================================
    // Basic DTO field @OakdomXssExclude
    // =========================================================================

    @Test
    void dtoFieldExclude_passesRawThroughFilter() throws Exception {
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        String rawBody = "{\"rawContent\":\"" + XSS + "\",\"title\":\"" + XSS + "\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/article");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_DTO_CLASS, ArticleDto.class);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        assertTrue(body.contains("\"rawContent\":\"" + XSS + "\""),
                "excluded DTO field must pass through unchanged");
        assertFalse(body.contains("\"title\":\"" + XSS + "\""),
                "non-annotated field must be sanitized");
        assertTrue(body.contains("\"title\":\"" + ESCAPED + "\""),
                "non-annotated field must contain escaped value");
    }

    // =========================================================================
    // Basic DTO field @OakdomXssFilterMode
    // =========================================================================

    @Test
    void dtoFieldFilterMode_appliesFieldLevelMode() throws Exception {
        // Base mode is BLACKLIST (global), but htmlBody has @OakdomXssFilterMode(WHITELIST).
        // Use <b> to distinguish modes: BLACKLIST escapes it, WHITELIST preserves it.
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        String rawBody = "{\"htmlBody\":\"<b>bold</b>\",\"title\":\"<b>bold</b>\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/article");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_DTO_CLASS, ArticleDto.class);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        // htmlBody uses WHITELIST → <b> is an allowed tag, preserved as-is
        assertTrue(body.contains("\"htmlBody\":\"<b>bold</b>\""),
                "htmlBody must use WHITELIST mode — allowed tag <b> must be preserved");
        // title uses BLACKLIST (base mode) → <b> is escaped
        assertTrue(body.contains("\"title\":\"&lt;b&gt;bold&lt;/b&gt;\""),
                "title must use BLACKLIST mode — <b> must be escaped");
    }

    // =========================================================================
    // Nested DTO excluded field
    // =========================================================================

    @Test
    void nestedDtoFieldExclude_passesRawThroughFilter() throws Exception {
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        String rawBody = "{\"title\":\"" + XSS + "\","
                + "\"author\":{\"bio\":\"" + XSS + "\",\"name\":\"" + XSS + "\"}}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/post");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_DTO_CLASS, PostDto.class);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        assertTrue(body.contains("\"bio\":\"" + XSS + "\""),
                "nested excluded field must pass through unchanged");
        assertFalse(body.contains("\"name\":\"" + XSS + "\""),
                "nested non-annotated field must be sanitized");
        assertFalse(body.contains("\"title\":\"" + XSS + "\""),
                "top-level non-annotated field must be sanitized");
    }

    // =========================================================================
    // No BODY_DTO_CLASS attribute — all strings sanitized with base mode
    // =========================================================================

    @Test
    void noDtoClass_allFieldsSanitizedWithBaseMode() throws Exception {
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        String rawBody = "{\"rawContent\":\"" + XSS + "\",\"title\":\"" + XSS + "\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/article");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        // No BODY_DTO_CLASS attribute — all fields sanitized uniformly

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        assertFalse(body.contains("<script>"), "all fields must be sanitized when no DTO class");
        assertTrue(body.contains(ESCAPED), "sanitized fields must contain escaped value");
    }

    // =========================================================================
    // Priority 1 (DTO field EXCLUDE) > Priority 2 (@RequestBody BLACKLIST)
    // =========================================================================

    @Test
    void dtoFieldExclude_beatsRequestBodyMode() throws Exception {
        // @RequestBody has BLACKLIST → would sanitize
        // DTO field rawField has @OakdomXssExclude → must pass through
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder().build());

        String rawBody = "{\"rawField\":\"" + XSS + "\",\"alwaysBlacklist\":\"" + XSS + "\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/post");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_DTO_CLASS, PriorityDto.class);
        request.setAttribute(OakdomXssRequestAttributes.BODY_MODE, FilterMode.BLACKLIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        assertTrue(body.contains("\"rawField\":\"" + XSS + "\""),
                "DTO field EXCLUDE must override @RequestBody BLACKLIST mode");
    }

    // =========================================================================
    // Priority 1 (DTO field BLACKLIST) > Priority 2 (@RequestBody WHITELIST)
    // =========================================================================

    @Test
    void dtoFieldBlacklist_beatsRequestBodyWhitelist() throws Exception {
        // @RequestBody base mode is WHITELIST → <b> would be preserved
        // DTO field alwaysBlacklist has @OakdomXssFilterMode(BLACKLIST) → <b> must be escaped
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder().build());

        String rawBody = "{\"alwaysBlacklist\":\"<b>bold</b>\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/post");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_DTO_CLASS, PriorityDto.class);
        request.setAttribute(OakdomXssRequestAttributes.BODY_MODE, FilterMode.WHITELIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        // BLACKLIST escapes <b>; WHITELIST would have preserved it
        assertTrue(body.contains("\"alwaysBlacklist\":\"&lt;b&gt;bold&lt;/b&gt;\""),
                "DTO field @OakdomXssFilterMode(BLACKLIST) must override @RequestBody WHITELIST — <b> must be escaped");
    }

    // =========================================================================
    // Priority 1 (DTO field EXCLUDE) > Priority 3 (method WHITELIST)
    // =========================================================================

    @Test
    void dtoFieldExclude_beatsMethodMode() throws Exception {
        // METHOD_MODE is WHITELIST → would strip tags from all fields
        // DTO field rawField has @OakdomXssExclude → must pass through
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder().build());

        String rawBody = "{\"rawField\":\"" + XSS + "\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/post");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_DTO_CLASS, PriorityDto.class);
        request.setAttribute(OakdomXssRequestAttributes.METHOD_MODE, FilterMode.WHITELIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        assertTrue(body.contains("\"rawField\":\"" + XSS + "\""),
                "DTO field EXCLUDE must override method-level WHITELIST mode");
    }

    // =========================================================================
    // Priority 1 (DTO field annotation) > Priority 4 (URL config WHITELIST rule)
    // =========================================================================

    @Test
    void dtoFieldBlacklist_beatsUrlConfigWhitelist() throws Exception {
        // URL config is WHITELIST for /api/editor/** → <b> would be preserved
        // DTO field alwaysBlacklist has @OakdomXssFilterMode(BLACKLIST) → <b> must be escaped
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRuleForUrl("/api/editor/**", FilterMode.WHITELIST)
                .build());

        String rawBody = "{\"alwaysBlacklist\":\"<b>bold</b>\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_DTO_CLASS, PriorityDto.class);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        // BLACKLIST escapes <b>; URL WHITELIST would have preserved it
        assertTrue(body.contains("\"alwaysBlacklist\":\"&lt;b&gt;bold&lt;/b&gt;\""),
                "DTO field @OakdomXssFilterMode(BLACKLIST) must override URL config WHITELIST — <b> must be escaped");
    }

    @Test
    void dtoFieldExclude_beatsUrlConfigWhitelist() throws Exception {
        // Config: WHITELIST for /api/editor/** → would strip tags
        // DTO field rawField has @OakdomXssExclude → must pass through
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRuleForUrl("/api/editor/**", FilterMode.WHITELIST)
                .build());

        String rawBody = "{\"rawField\":\"" + XSS + "\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_DTO_CLASS, PriorityDto.class);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        assertTrue(body.contains("\"rawField\":\"" + XSS + "\""),
                "DTO field EXCLUDE must override URL config WHITELIST rule");
    }

    // =========================================================================
    // Priority 2 (@RequestBody EXCLUDE) gates DTO field annotations — whole body skipped
    // =========================================================================

    @Test
    void requestBodyExclude_skipsEntireBody_ignoringDtoFieldAnnotations() throws Exception {
        // BODY_EXCLUDE set → the entire body is returned as-is, regardless of DTO annotations
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        String rawBody = "{\"rawField\":\"" + XSS + "\",\"alwaysBlacklist\":\"" + XSS + "\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/post");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_DTO_CLASS, PriorityDto.class);
        request.setAttribute(OakdomXssRequestAttributes.BODY_EXCLUDE, Boolean.TRUE);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        // Entire body passes through — both fields are raw
        assertTrue(body.contains("\"rawField\":\"" + XSS + "\""),
                "excluded body: rawField must pass through");
        assertTrue(body.contains("\"alwaysBlacklist\":\"" + XSS + "\""),
                "excluded body: alwaysBlacklist must also pass through (body is not processed at all)");
    }

    // =========================================================================
    // Priority 3 (EXCLUDE_ALL — method-level) gates DTO field annotations — whole body skipped
    // =========================================================================

    @Test
    void excludeAll_skipsEntireBody_ignoringDtoFieldAnnotations() throws Exception {
        // EXCLUDE_ALL set → the entire request is excluded, body passes through raw
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        String rawBody = "{\"alwaysBlacklist\":\"" + XSS + "\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/post");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_DTO_CLASS, PriorityDto.class);
        request.setAttribute(OakdomXssRequestAttributes.EXCLUDE_ALL, Boolean.TRUE);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        assertTrue(body.contains("\"alwaysBlacklist\":\"" + XSS + "\""),
                "EXCLUDE_ALL must skip body entirely — DTO field annotations have no effect");
    }

    // =========================================================================
    // Priority 2 (@RequestBody BLACKLIST) > Priority 4 (URL WHITELIST config)
    // =========================================================================

    @Test
    void requestBodyBlacklist_beatsUrlConfigWhitelist() throws Exception {
        // URL config is WHITELIST for /api/editor/** → <b> would be preserved
        // BODY_MODE BLACKLIST → <b> must be escaped instead
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRuleForUrl("/api/editor/**", FilterMode.WHITELIST)
                .build());

        String rawBody = "{\"content\":\"<b>bold</b>\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_MODE, FilterMode.BLACKLIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        // BLACKLIST escapes <b>; URL WHITELIST would have preserved it
        assertTrue(body.contains("&lt;b&gt;bold&lt;/b&gt;"),
                "@RequestBody BLACKLIST must override URL config WHITELIST — <b> must be escaped");
    }

    // =========================================================================
    // Priority 3 (method BLACKLIST) > Priority 4 (URL WHITELIST config)
    // =========================================================================

    @Test
    void methodBlacklist_beatsUrlConfigWhitelistForBody() throws Exception {
        // URL config is WHITELIST for /api/editor/** → <b> would be preserved
        // METHOD_MODE BLACKLIST → <b> must be escaped instead
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRuleForUrl("/api/editor/**", FilterMode.WHITELIST)
                .build());

        String rawBody = "{\"content\":\"<b>bold</b>\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.METHOD_MODE, FilterMode.BLACKLIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        // BLACKLIST escapes <b>; URL WHITELIST would have preserved it
        assertTrue(body.contains("&lt;b&gt;bold&lt;/b&gt;"),
                "method BLACKLIST must override URL config WHITELIST for body — <b> must be escaped");
    }

    // =========================================================================
    // Priority 4 (URL WHITELIST) > Priority 5 (global BLACKLIST)
    // =========================================================================

    @Test
    void urlConfigWhitelist_beatsGlobalBlacklist_forBody() throws Exception {
        // Config: global BLACKLIST, but WHITELIST rule for /api/editor/**
        // BLACKLIST escapes <b> → "&lt;b&gt;"; WHITELIST allows <b> and keeps it as-is.
        // Verifies the URL rule (P4) wins over the global mode (P5).
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .filterRuleForUrl("/api/editor/**", FilterMode.WHITELIST)
                .build());

        String rawBody = "{\"content\":\"<b>bold</b>" + XSS + "\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        // WHITELIST keeps allowed tags intact — <b> is preserved (BLACKLIST would escape it)
        assertTrue(body.contains("<b>bold</b>"),
                "URL WHITELIST rule must preserve allowed tags; BLACKLIST would have escaped them");
        assertFalse(body.contains("<script>"), "script tag must not appear in output");
    }

    // =========================================================================
    // List<String> — each element sanitized when no DTO class
    // =========================================================================

    @Test
    void listOfString_allElementsSanitized_throughFilter() throws Exception {
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        String rawBody = "{\"tags\":[\"" + XSS + "\",\"safe\"]}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/tags");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_DTO_CLASS, TagsDto.class);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");

        assertFalse(body.contains("<script>"), "all list elements must be sanitized");
        assertTrue(body.contains("safe"), "safe value must remain");
    }
}
