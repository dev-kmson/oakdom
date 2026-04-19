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

class OakdomXssFilterAnnotationTest {

    private static final String XSS_INPUT = "<script>alert(1)</script>";
    private static final String XSS_ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;";

    private final OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder().build());

    private static byte[] readAllBytes(InputStream in) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = in.read(chunk)) != -1) {
            buffer.write(chunk, 0, n);
        }
        return buffer.toByteArray();
    }

    // -------------------------------------------------------------------------
    // EXCLUDE_ALL — all parameters pass through unsanitized
    // -------------------------------------------------------------------------

    @Test
    void excludeAllAttributeSkipsAllParamSanitization() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("name", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.EXCLUDE_ALL, Boolean.TRUE);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_INPUT, wrapped.getParameter("name"));
    }

    // -------------------------------------------------------------------------
    // PARAM_EXCLUDE_PREFIX — only the named parameter passes through
    // -------------------------------------------------------------------------

    @Test
    void paramExcludeAttributeSkipsOnlyThatParameter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("raw", XSS_INPUT);
        request.setParameter("title", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.PARAM_EXCLUDE_PREFIX + "raw", Boolean.TRUE);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_INPUT, wrapped.getParameter("raw"));
        assertEquals(XSS_ESCAPED, wrapped.getParameter("title"));
    }

    // -------------------------------------------------------------------------
    // PARAM_MODE_PREFIX — per-parameter mode override
    // -------------------------------------------------------------------------

    @Test
    void paramModeAttributeOverridesGlobalModeForThatParameter() throws Exception {
        // Set up a global BLACKLIST config, but override 'content' param to WHITELIST
        // (WHITELIST allows safe tags through but strips scripts)
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("content", XSS_INPUT);
        request.setParameter("title", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.PARAM_MODE_PREFIX + "content", FilterMode.WHITELIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        // WHITELIST strips the <script> tag entirely
        assertFalse(wrapped.getParameter("content").contains("<script>"));
        // title still uses BLACKLIST — escaped
        assertEquals(XSS_ESCAPED, wrapped.getParameter("title"));
    }

    // -------------------------------------------------------------------------
    // METHOD_MODE — method-level mode applies to all parameters without param override
    // -------------------------------------------------------------------------

    @Test
    void methodModeAttributeAppliesWhenNoParamModeOverride() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("content", XSS_INPUT);
        request.setAttribute(OakdomXssRequestAttributes.METHOD_MODE, FilterMode.WHITELIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        // WHITELIST strips <script>
        assertFalse(wrapped.getParameter("content").contains("<script>"));
    }

    @Test
    void paramModeAttributeTakesPriorityOverMethodMode() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("title", XSS_INPUT);
        // Method says WHITELIST, but param overrides back to BLACKLIST
        request.setAttribute(OakdomXssRequestAttributes.METHOD_MODE, FilterMode.WHITELIST);
        request.setAttribute(OakdomXssRequestAttributes.PARAM_MODE_PREFIX + "title", FilterMode.BLACKLIST);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertEquals(XSS_ESCAPED, wrapped.getParameter("title"));
    }

    // -------------------------------------------------------------------------
    // BODY_EXCLUDE — JSON body passes through unsanitized
    // -------------------------------------------------------------------------

    @Test
    void bodyExcludeAttributeSkipsJsonBodySanitization() throws Exception {
        String rawBody = "{\"content\":\"" + XSS_INPUT + "\"}";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.BODY_EXCLUDE, Boolean.TRUE);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        byte[] body = readAllBytes(wrapped.getInputStream());
        assertEquals(rawBody, new String(body, "UTF-8"));
    }

    // -------------------------------------------------------------------------
    // EXCLUDE_ALL also skips JSON body
    // -------------------------------------------------------------------------

    @Test
    void excludeAllAttributeAlsoSkipsJsonBody() throws Exception {
        String rawBody = "{\"content\":\"" + XSS_INPUT + "\"}";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContentType("application/json");
        request.setContent(rawBody.getBytes("UTF-8"));
        request.setAttribute(OakdomXssRequestAttributes.EXCLUDE_ALL, Boolean.TRUE);

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        byte[] body = readAllBytes(wrapped.getInputStream());
        assertEquals(rawBody, new String(body, "UTF-8"));
    }
}
