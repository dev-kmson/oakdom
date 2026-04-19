package io.oakdom.xss.filter;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.xss.config.XssConfig;
import io.oakdom.xss.interceptor.OakdomXssRequestAttributes;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies the full six-level priority order:
 *
 * <ol>
 *   <li>Parameter-level annotation</li>
 *   <li>Method-level annotation</li>
 *   <li>Config rule — URL pattern + parameter name</li>
 *   <li>Config rule — parameter name only</li>
 *   <li>Config rule — URL pattern only</li>
 *   <li>Global filter mode</li>
 * </ol>
 */
class OakdomXssFilterPriorityTest {

    private static final String XSS_INPUT   = "<script>alert(1)</script>";
    private static final String XSS_ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;";

    private static byte[] readAllBytes(InputStream in) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = in.read(chunk)) != -1) buf.write(chunk, 0, n);
        return buf.toByteArray();
    }

    // =========================================================================
    // Priority 1 (param annotation) > Priority 3 (URL+param config rule)
    // =========================================================================

    @Test
    void paramAnnotationExclude_beatsPriority3UrlPlusParamRule() throws Exception {
        // Config: WHITELIST for /api/editor/** + content → would strip <script>
        // Annotation: EXCLUDE on content → raw value must pass through
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRule("/api/editor/**", "content", FilterMode.WHITELIST)
                .build());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setParameter("content", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.PARAM_EXCLUDE_PREFIX + "content", Boolean.TRUE);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_INPUT, wrapped.getParameter("content"));
    }

    @Test
    void paramAnnotationMode_beatsPriority3UrlPlusParamRule() throws Exception {
        // Config: WHITELIST for /api/editor/** + content → would strip <script>
        // Annotation: BLACKLIST on content → must escape instead
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRule("/api/editor/**", "content", FilterMode.WHITELIST)
                .build());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setParameter("content", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.PARAM_MODE_PREFIX + "content", FilterMode.BLACKLIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_ESCAPED, wrapped.getParameter("content"));
    }

    // =========================================================================
    // Priority 1 (param annotation) > Priority 4 (param-only config rule)
    // =========================================================================

    @Test
    void paramAnnotationExclude_beatsPriority4ParamOnlyRule() throws Exception {
        // Config: WHITELIST for param 'content' on any URL → would strip <script>
        // Annotation: EXCLUDE on content → raw value must pass through
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRuleForParam("content", FilterMode.WHITELIST)
                .build());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/post");
        request.setParameter("content", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.PARAM_EXCLUDE_PREFIX + "content", Boolean.TRUE);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_INPUT, wrapped.getParameter("content"));
    }

    @Test
    void paramAnnotationMode_beatsPriority4ParamOnlyRule() throws Exception {
        // Config: WHITELIST for param 'content' → would strip <script>
        // Annotation: BLACKLIST on content → must escape instead
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRuleForParam("content", FilterMode.WHITELIST)
                .build());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/post");
        request.setParameter("content", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.PARAM_MODE_PREFIX + "content", FilterMode.BLACKLIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_ESCAPED, wrapped.getParameter("content"));
    }

    // =========================================================================
    // Priority 1 (param annotation) > Priority 5 (URL-only config rule)
    // =========================================================================

    @Test
    void paramAnnotationMode_beatsPriority5UrlOnlyRule() throws Exception {
        // Config: WHITELIST for /api/editor/** (any param) → would strip <script>
        // Annotation: BLACKLIST on content → must escape instead
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRuleForUrl("/api/editor/**", FilterMode.WHITELIST)
                .build());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setParameter("content", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.PARAM_MODE_PREFIX + "content", FilterMode.BLACKLIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_ESCAPED, wrapped.getParameter("content"));
    }

    // =========================================================================
    // Priority 1 (param annotation) > Priority 6 (global filter mode)
    // =========================================================================

    @Test
    void paramAnnotationExclude_beatsPriority6GlobalMode() throws Exception {
        // Config: global BLACKLIST → would escape
        // Annotation: EXCLUDE on content → raw value must pass through
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/post");
        request.setParameter("content", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.PARAM_EXCLUDE_PREFIX + "content", Boolean.TRUE);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_INPUT, wrapped.getParameter("content"));
    }

    // =========================================================================
    // Priority 2 (method annotation) > Priority 3 (URL+param config rule)
    // =========================================================================

    @Test
    void methodAnnotationExclude_beatsPriority3UrlPlusParamRule() throws Exception {
        // Config: WHITELIST for /api/editor/** + content → would strip <script>
        // Annotation: EXCLUDE_ALL → raw value must pass through
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRule("/api/editor/**", "content", FilterMode.WHITELIST)
                .build());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setParameter("content", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.EXCLUDE_ALL, Boolean.TRUE);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_INPUT, wrapped.getParameter("content"));
    }

    @Test
    void methodAnnotationMode_beatsPriority3UrlPlusParamRule() throws Exception {
        // Config: WHITELIST for /api/editor/** + content → would strip <script>
        // Annotation: METHOD_MODE BLACKLIST → must escape instead
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRule("/api/editor/**", "content", FilterMode.WHITELIST)
                .build());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setParameter("content", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.METHOD_MODE, FilterMode.BLACKLIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_ESCAPED, wrapped.getParameter("content"));
    }

    // =========================================================================
    // Priority 2 (method annotation) > Priority 4 (param-only config rule)
    // =========================================================================

    @Test
    void methodAnnotationMode_beatsPriority4ParamOnlyRule() throws Exception {
        // Config: WHITELIST for param 'content' → would strip <script>
        // Annotation: METHOD_MODE BLACKLIST → must escape instead
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRuleForParam("content", FilterMode.WHITELIST)
                .build());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/post");
        request.setParameter("content", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.METHOD_MODE, FilterMode.BLACKLIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_ESCAPED, wrapped.getParameter("content"));
    }

    // =========================================================================
    // Priority 2 (method annotation) > Priority 5 (URL-only config rule)
    // =========================================================================

    @Test
    void methodAnnotationMode_beatsPriority5UrlOnlyRule() throws Exception {
        // Config: WHITELIST for /api/editor/** → would strip <script>
        // Annotation: METHOD_MODE BLACKLIST → must escape instead
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRuleForUrl("/api/editor/**", FilterMode.WHITELIST)
                .build());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setParameter("content", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.METHOD_MODE, FilterMode.BLACKLIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_ESCAPED, wrapped.getParameter("content"));
    }

    // =========================================================================
    // Priority 1 > Priority 2 (param annotation beats method annotation)
    // =========================================================================

    @Test
    void paramAnnotationExclude_beatsMethodAnnotationMode() throws Exception {
        // Method annotation: WHITELIST → would strip <script>
        // Param annotation: EXCLUDE on content → raw value must pass through
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder().build());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/post");
        request.setParameter("content", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.METHOD_MODE, FilterMode.WHITELIST);
        request.setAttribute(OakdomXssRequestAttributes.PARAM_EXCLUDE_PREFIX + "content", Boolean.TRUE);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_INPUT, wrapped.getParameter("content"));
    }

    // =========================================================================
    // JSON body — annotation beats config URL rule
    // =========================================================================

    @Test
    void bodyAnnotationExclude_beatsConfigUrlRule() throws Exception {
        // Config: WHITELIST for /api/editor/** → would strip <script> from body
        // Annotation: BODY_EXCLUDE → raw body must pass through
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRuleForUrl("/api/editor/**", FilterMode.WHITELIST)
                .build());

        String rawBody = "{\"content\":\"" + XSS_INPUT + "\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_EXCLUDE, Boolean.TRUE);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");
        assertEquals(rawBody, body);
    }

    @Test
    void bodyAnnotationMode_beatsConfigUrlRule() throws Exception {
        // Config: WHITELIST for /api/editor/** → would strip <script> from body
        // Annotation: BODY_MODE BLACKLIST → must escape instead
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .filterRuleForUrl("/api/editor/**", FilterMode.WHITELIST)
                .build());

        String rawBody = "{\"content\":\"" + XSS_INPUT + "\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/editor/1");
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_MODE, FilterMode.BLACKLIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = new String(readAllBytes(wrapped.getInputStream()), "UTF-8");
        assertTrue(body.contains(XSS_ESCAPED.replace("<", "&lt;").replace(">", "&gt;")));
        assertFalse(body.contains("<script>"));
    }
}
