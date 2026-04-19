package io.oakdom.xss.filter;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.xss.config.XssConfig;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class OakdomXssFilterJsonBodyTest {

    private static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private MockHttpServletRequest jsonRequest(String uri, String body) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(uri);
        request.setContentType(CONTENT_TYPE_JSON);
        request.setCharacterEncoding("UTF-8");
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        return request;
    }

    private String readBody(HttpServletRequest request) throws IOException {
        StringBuilder sb = new StringBuilder();
        java.io.BufferedReader reader = request.getReader();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // Global BLACKLIST mode (default)
    // -------------------------------------------------------------------------

    @Test
    void jsonBody_blacklistMode_sanitizesStringValues() throws Exception {
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        MockHttpServletRequest request = jsonRequest("/api/article",
                "{\"title\":\"<script>alert(1)</script>\",\"count\":42}");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = readBody(wrapped);

        assertThat(body).contains("&lt;script&gt;");
        assertThat(body).contains("42");
    }

    @Test
    void jsonBody_blacklistMode_preservesNonStringValues() throws Exception {
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        MockHttpServletRequest request = jsonRequest("/api/article",
                "{\"count\":42,\"flag\":true,\"value\":null}");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = readBody(wrapped);

        assertThat(body).contains("42");
        assertThat(body).contains("true");
        assertThat(body).contains("null");
    }

    // -------------------------------------------------------------------------
    // URL-level rule — WHITELIST
    // -------------------------------------------------------------------------

    @Test
    void jsonBody_urlWhitelistRule_appliesWhitelistMode() throws Exception {
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .filterRuleForUrl("/api/editor/**", FilterMode.WHITELIST)
                .build());

        MockHttpServletRequest request = jsonRequest("/api/editor/post",
                "{\"content\":\"<b>bold</b><script>alert(1)</script>\"}");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = readBody(wrapped);

        assertThat(body).contains("<b>bold</b>");
        assertThat(body).doesNotContain("<script>");
    }

    @Test
    void jsonBody_noMatchingUrlRule_usesGlobalMode() throws Exception {
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .filterRuleForUrl("/api/editor/**", FilterMode.WHITELIST)
                .build());

        MockHttpServletRequest request = jsonRequest("/api/article",
                "{\"title\":\"<script>alert(1)</script>\"}");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = readBody(wrapped);

        assertThat(body).contains("&lt;script&gt;");
    }

    // -------------------------------------------------------------------------
    // Exclude URL — body skipped
    // -------------------------------------------------------------------------

    @Test
    void jsonBody_excludedUrl_bodyNotSanitized() throws Exception {
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .excludeUrl("/api/raw/**")
                .build());

        String rawBody = "{\"data\":\"<script>alert(1)</script>\"}";
        MockHttpServletRequest request = jsonRequest("/api/raw/upload", rawBody);
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = readBody(wrapped);

        assertThat(body).contains("<script>alert(1)</script>");
    }

    // -------------------------------------------------------------------------
    // Body caching — readable multiple times
    // -------------------------------------------------------------------------

    @Test
    void jsonBody_readMultipleTimes_returnsSameContent() throws Exception {
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        MockHttpServletRequest request = jsonRequest("/api/article",
                "{\"title\":\"<script>xss</script>\"}");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String first = readBody(wrapped);
        // getInputStream() again — should return cached result
        java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(wrapped.getInputStream(), StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        String second = sb.toString();

        assertThat(first).isEqualTo(second);
        assertThat(first).contains("&lt;script&gt;");
    }

    // -------------------------------------------------------------------------
    // Non-JSON request — body untouched
    // -------------------------------------------------------------------------

    @Test
    void nonJsonRequest_bodyNotIntercepted() throws Exception {
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/upload");
        request.setContentType("application/octet-stream");
        request.setContent(new byte[]{1, 2, 3});

        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        // No exception — body passthrough is fine
        assertThat(chain.getRequest()).isNotNull();
    }

    // -------------------------------------------------------------------------
    // Nested JSON and arrays
    // -------------------------------------------------------------------------

    @Test
    void jsonBody_nestedObject_sanitizesAllStringValues() throws Exception {
        OakdomXssFilter filter = new OakdomXssFilter(XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .build());

        MockHttpServletRequest request = jsonRequest("/api/article",
                "{\"author\":{\"name\":\"<script>xss</script>\"},\"tags\":[\"<b>tag</b>\",\"safe\"]}");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        String body = readBody(wrapped);

        assertThat(body).contains("&lt;script&gt;");
        assertThat(body).contains("&lt;b&gt;tag&lt;/b&gt;");
        assertThat(body).contains("safe");
    }
}
