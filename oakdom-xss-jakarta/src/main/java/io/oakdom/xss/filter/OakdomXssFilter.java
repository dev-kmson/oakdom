package io.oakdom.xss.filter;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.core.matcher.UrlPatternMatcher;
import io.oakdom.core.resolver.ContentTypeResolver;
import io.oakdom.web.filter.OakdomFilter;
import io.oakdom.xss.config.XssConfig;
import io.oakdom.xss.interceptor.OakdomXssRequestAttributes;
import io.oakdom.xss.processor.OakdomXssJsonRequestProcessor;
import io.oakdom.xss.sanitizer.DefaultXssSanitizer;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * XSS servlet filter that sanitizes all incoming HTTP request parameters
 * and JSON request bodies.
 *
 * <p>Implements both {@link OakdomFilter} (for filter-mode resolution and exclusion logic)
 * and {@link Filter} (for servlet integration). On each request:
 * <ul>
 *   <li>Parameter values ({@code application/x-www-form-urlencoded},
 *       {@code multipart/form-data}, query string) are sanitized lazily when accessed
 *       via {@code getParameter()}, {@code getParameterValues()}, or
 *       {@code getParameterMap()}.</li>
 *   <li>JSON request bodies ({@code application/json}) are sanitized lazily when the
 *       body is first read via {@code getInputStream()} or {@code getReader()}.
 *       All string values within the JSON structure are sanitized; non-string values
 *       (numbers, booleans, nulls) are preserved. The sanitized body is cached so it
 *       can be read multiple times.</li>
 * </ul>
 *
 * <p>For JSON body filtering, only URL-pattern rules and the global filter mode apply.
 * Parameter-specific rules ({@code filterRuleForParam}) are not applicable to body content.
 *
 * <p>This variant targets {@code jakarta.servlet} environments (Tomcat 10+).
 * For {@code javax.servlet} environments (Tomcat 9 or below), use
 * {@code oakdom-xss} instead.
 *
 * <h3>Usage — legacy Spring MVC (jakarta.servlet)</h3>
 * <p>Extend this class and override {@link #configure()} to provide a custom
 * {@link XssConfig}. Register the subclass as a servlet filter in {@code web.xml}:
 * <pre>{@code
 * public class MyXssFilter extends OakdomXssFilter {
 *     &#64;Override
 *     protected XssConfig configure() {
 *         return XssConfig.builder()
 *             .globalFilterMode(FilterMode.BLACKLIST)
 *             .filterRule("/api/editor/**", "content", FilterMode.WHITELIST)
 *             .build();
 *     }
 * }
 * }</pre>
 * <pre>{@code
 * <!-- web.xml -->
 * <filter>
 *     <filter-name>xssFilter</filter-name>
 *     <filter-class>com.example.MyXssFilter</filter-class>
 * </filter>
 * <filter-mapping>
 *     <filter-name>xssFilter</filter-name>
 *     <url-pattern>/*</url-pattern>
 * </filter-mapping>
 * }</pre>
 *
 * <h3>Filter mode priority</h3>
 * <ol>
 *   <li>Rule matching both URL pattern and parameter name (most specific)</li>
 *   <li>Rule matching parameter name only</li>
 *   <li>Rule matching URL pattern only</li>
 *   <li>Global filter mode (least specific)</li>
 * </ol>
 */
public class OakdomXssFilter implements OakdomFilter, Filter {

    private final XssConfig config;
    private final DefaultXssSanitizer blacklistSanitizer;
    private final DefaultXssSanitizer whitelistSanitizer;
    private final OakdomXssJsonRequestProcessor jsonProcessor;

    /**
     * Creates a filter using the configuration returned by {@link #configure()}.
     * Intended for subclasses that override {@link #configure()}.
     */
    public OakdomXssFilter() {
        this.config = configure();
        this.blacklistSanitizer = DefaultXssSanitizer.of(FilterMode.BLACKLIST, this.config);
        this.whitelistSanitizer = DefaultXssSanitizer.of(FilterMode.WHITELIST, this.config);
        this.jsonProcessor = new OakdomXssJsonRequestProcessor(blacklistSanitizer, whitelistSanitizer);
    }

    /**
     * Creates a filter with the given configuration.
     *
     * @param config the XSS configuration to use; must not be {@code null}
     */
    public OakdomXssFilter(XssConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("config must not be null");
        }
        this.config = config;
        this.blacklistSanitizer = DefaultXssSanitizer.of(FilterMode.BLACKLIST, config);
        this.whitelistSanitizer = DefaultXssSanitizer.of(FilterMode.WHITELIST, config);
        this.jsonProcessor = new OakdomXssJsonRequestProcessor(blacklistSanitizer, whitelistSanitizer);
    }

    // -------------------------------------------------------------------------
    // jakarta.servlet.Filter
    // -------------------------------------------------------------------------

    /**
     * No-op. Configuration is provided via {@link #configure()} or the constructor.
     *
     * @param filterConfig the filter configuration provided by the servlet container
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    /**
     * Wraps the incoming {@link HttpServletRequest} with an XSS-sanitizing wrapper
     * and passes it down the filter chain.
     *
     * <p>Parameter values are sanitized lazily — only when accessed by downstream
     * code via {@code getParameter()}, {@code getParameterValues()}, or
     * {@code getParameterMap()}.
     *
     * <p>JSON request bodies ({@code application/json}) are also sanitized lazily —
     * only when first read via {@code getInputStream()} or {@code getReader()}.
     * The sanitized body is cached so it can be read multiple times.
     *
     * @param request  the incoming servlet request
     * @param response the servlet response
     * @param chain    the filter chain
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            chain.doFilter(new XssHttpRequestWrapper((HttpServletRequest) request), response);
        } else {
            chain.doFilter(request, response);
        }
    }

    /**
     * No-op.
     */
    @Override
    public void destroy() {
    }

    // -------------------------------------------------------------------------
    // Sanitization
    // -------------------------------------------------------------------------

    /**
     * Sanitizes the given value using the sanitizer configured for the specified
     * {@link FilterMode}.
     *
     * <p>The sanitizer reflects any customizations ({@code addEscapeChar},
     * {@code addAllowedTag}, etc.) defined in the {@link XssConfig} this filter
     * was constructed with.
     *
     * @param value      the raw input value; may be {@code null}
     * @param filterMode the filter mode to apply; must not be {@code null}
     * @return the sanitized value, or {@code null} if {@code value} is {@code null}
     */
    public String sanitize(String value, FilterMode filterMode) {
        return (filterMode == FilterMode.WHITELIST ? whitelistSanitizer : blacklistSanitizer).sanitize(value);
    }

    // -------------------------------------------------------------------------
    // OakdomFilter
    // -------------------------------------------------------------------------

    /**
     * Returns the {@link XssConfig} to use for this filter.
     *
     * <p>Subclasses can override this method to provide custom configuration
     * instead of passing a config to the constructor. The default implementation
     * returns a config with {@link FilterMode#BLACKLIST} as the global mode.
     *
     * <p><strong>Note:</strong> This method is called from the constructor.
     * Implementations must not reference subclass instance fields, as they will
     * not yet be initialized at the time this method is invoked.
     *
     * @return the XSS configuration; never {@code null}
     */
    protected XssConfig configure() {
        return XssConfig.builder().build();
    }

    /**
     * Returns {@code true} if the given request URI and parameter combination
     * matches any of the configured exclude rules.
     *
     * @param requestUri    the request URI
     * @param parameterName the parameter name
     * @return {@code true} if filtering should be skipped
     */
    @Override
    public boolean shouldSkip(String requestUri, String parameterName) {
        for (XssConfig.ExcludeRule rule : config.getExcludeRules()) {
            if (matchesExcludeRule(rule, requestUri, parameterName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Resolves the {@link FilterMode} for the given request URI and parameter name
     * by evaluating the configured filter rules in priority order.
     *
     * @param requestUri    the request URI
     * @param parameterName the parameter name
     * @return the resolved {@link FilterMode}; never {@code null}
     */
    @Override
    public FilterMode resolveFilterMode(String requestUri, String parameterName) {
        // Priority 1: rule matching both URL pattern and parameter name
        for (XssConfig.FilterRule rule : config.getFilterRules()) {
            if (rule.getUrlPattern() != null && rule.getParameterName() != null) {
                if (matchesUrl(rule.getUrlPattern(), requestUri)
                        && matchesParameter(rule.getParameterName(), parameterName)) {
                    return rule.getFilterMode();
                }
            }
        }
        // Priority 2: rule matching parameter name only (applies to any URL)
        for (XssConfig.FilterRule rule : config.getFilterRules()) {
            if (rule.getUrlPattern() == null && rule.getParameterName() != null) {
                if (matchesParameter(rule.getParameterName(), parameterName)) {
                    return rule.getFilterMode();
                }
            }
        }
        // Priority 3: rule matching URL pattern only (applies to any parameter)
        for (XssConfig.FilterRule rule : config.getFilterRules()) {
            if (rule.getUrlPattern() != null && rule.getParameterName() == null) {
                if (matchesUrl(rule.getUrlPattern(), requestUri)) {
                    return rule.getFilterMode();
                }
            }
        }
        return config.getGlobalFilterMode();
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private boolean matchesExcludeRule(XssConfig.ExcludeRule rule, String requestUri, String parameterName) {
        String urlPattern = rule.getUrlPattern();
        String paramName = rule.getParameterName();

        if (urlPattern != null && paramName != null) {
            return matchesUrl(urlPattern, requestUri) && matchesParameter(paramName, parameterName);
        }
        if (urlPattern != null) {
            return matchesUrl(urlPattern, requestUri);
        }
        if (paramName != null) {
            return matchesParameter(paramName, parameterName);
        }
        return false;
    }

    private boolean matchesUrl(String pattern, String requestUri) {
        if (requestUri == null) {
            return false;
        }
        return new UrlPatternMatcher(Collections.singletonList(pattern)).matches(requestUri);
    }

    private boolean matchesParameter(String paramName, String parameterName) {
        return paramName.equals(parameterName);
    }

    // -------------------------------------------------------------------------
    // Inner class: HTTP request wrapper
    // -------------------------------------------------------------------------

    /**
     * {@link HttpServletRequestWrapper} that sanitizes parameter values and JSON
     * request bodies on access.
     */
    private class XssHttpRequestWrapper extends HttpServletRequestWrapper {

        private final String requestUri;
        private final boolean isJsonBody;
        private byte[] cachedBody;

        XssHttpRequestWrapper(HttpServletRequest request) {
            super(request);
            this.requestUri = request.getRequestURI();
            this.isJsonBody = ContentTypeResolver.isJson(request.getContentType());
        }

        @Override
        public String getParameter(String name) {
            if (isParamExcluded(name)) {
                return super.getParameter(name);
            }
            String value = super.getParameter(name);
            if (value == null) {
                return null;
            }
            return sanitize(value, resolveParamFilterMode(name));
        }

        @Override
        public String[] getParameterValues(String name) {
            if (isParamExcluded(name)) {
                return super.getParameterValues(name);
            }
            String[] values = super.getParameterValues(name);
            if (values == null) {
                return null;
            }
            FilterMode mode = resolveParamFilterMode(name);
            String[] sanitized = new String[values.length];
            for (int i = 0; i < values.length; i++) {
                sanitized[i] = sanitize(values[i], mode);
            }
            return sanitized;
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            Map<String, String[]> original = super.getParameterMap();
            Map<String, String[]> result = new LinkedHashMap<>();
            for (Map.Entry<String, String[]> entry : original.entrySet()) {
                String name = entry.getKey();
                if (isParamExcluded(name)) {
                    result.put(name, entry.getValue());
                } else {
                    FilterMode mode = resolveParamFilterMode(name);
                    String[] values = entry.getValue();
                    String[] sanitized = new String[values.length];
                    for (int i = 0; i < values.length; i++) {
                        sanitized[i] = sanitize(values[i], mode);
                    }
                    result.put(name, sanitized);
                }
            }
            return Collections.unmodifiableMap(result);
        }

        private boolean isParamExcluded(String name) {
            if (Boolean.TRUE.equals(getAttribute(OakdomXssRequestAttributes.EXCLUDE_ALL))) {
                return true;
            }
            if (Boolean.TRUE.equals(getAttribute(OakdomXssRequestAttributes.PARAM_EXCLUDE_PREFIX + name))) {
                return true;
            }
            return shouldSkip(requestUri, name);
        }

        private FilterMode resolveParamFilterMode(String name) {
            Object paramMode = getAttribute(OakdomXssRequestAttributes.PARAM_MODE_PREFIX + name);
            if (paramMode instanceof FilterMode) {
                return (FilterMode) paramMode;
            }
            Object methodMode = getAttribute(OakdomXssRequestAttributes.METHOD_MODE);
            if (methodMode instanceof FilterMode) {
                return (FilterMode) methodMode;
            }
            return resolveFilterMode(requestUri, name);
        }

        /**
         * Returns the request body as a sanitized {@link ServletInputStream} for
         * {@code application/json} requests. For other content types, delegates to
         * the original request.
         *
         * <p>The sanitized body is cached after the first read so it can be read
         * multiple times.
         */
        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (!isJsonBody) {
                return super.getInputStream();
            }
            return new CachedBodyServletInputStream(getOrReadBody());
        }

        /**
         * Returns the request body as a sanitized {@link BufferedReader} for
         * {@code application/json} requests. For other content types, delegates to
         * the original request.
         *
         * <p>The sanitized body is cached after the first read so it can be read
         * multiple times.
         */
        @Override
        public BufferedReader getReader() throws IOException {
            if (!isJsonBody) {
                return super.getReader();
            }
            String encoding = getCharacterEncoding();
            if (encoding == null) {
                encoding = "UTF-8";
            }
            return new BufferedReader(new InputStreamReader(
                    new ByteArrayInputStream(getOrReadBody()), encoding));
        }

        private synchronized byte[] getOrReadBody() throws IOException {
            if (cachedBody == null) {
                byte[] rawBytes = readBytes(super.getInputStream());
                if (shouldSkipBody()) {
                    cachedBody = rawBytes;
                } else {
                    String encoding = getCharacterEncoding();
                    if (encoding == null) {
                        encoding = "UTF-8";
                    }
                    String raw = new String(rawBytes, encoding);
                    FilterMode mode = resolveFilterModeForBody();
                    String sanitized = jsonProcessor.process(raw, mode);
                    cachedBody = sanitized.getBytes(encoding);
                }
            }
            return cachedBody;
        }

        private boolean shouldSkipBody() {
            if (Boolean.TRUE.equals(getAttribute(OakdomXssRequestAttributes.EXCLUDE_ALL))) {
                return true;
            }
            if (Boolean.TRUE.equals(getAttribute(OakdomXssRequestAttributes.BODY_EXCLUDE))) {
                return true;
            }
            for (XssConfig.ExcludeRule rule : config.getExcludeRules()) {
                if (rule.getUrlPattern() != null && rule.getParameterName() == null) {
                    if (matchesUrl(rule.getUrlPattern(), requestUri)) {
                        return true;
                    }
                }
            }
            return false;
        }

        private FilterMode resolveFilterModeForBody() {
            Object bodyMode = getAttribute(OakdomXssRequestAttributes.BODY_MODE);
            if (bodyMode instanceof FilterMode) {
                return (FilterMode) bodyMode;
            }
            Object methodMode = getAttribute(OakdomXssRequestAttributes.METHOD_MODE);
            if (methodMode instanceof FilterMode) {
                return (FilterMode) methodMode;
            }
            for (XssConfig.FilterRule rule : config.getFilterRules()) {
                if (rule.getUrlPattern() != null && rule.getParameterName() == null) {
                    if (matchesUrl(rule.getUrlPattern(), requestUri)) {
                        return rule.getFilterMode();
                    }
                }
            }
            return config.getGlobalFilterMode();
        }

        private byte[] readBytes(InputStream inputStream) throws IOException {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int n;
            while ((n = inputStream.read(chunk)) != -1) {
                buffer.write(chunk, 0, n);
            }
            return buffer.toByteArray();
        }
    }

    // -------------------------------------------------------------------------
    // Inner class: cached body servlet input stream
    // -------------------------------------------------------------------------

    /**
     * {@link ServletInputStream} backed by a cached byte array.
     *
     * <p>Used to allow the request body to be read multiple times after it has
     * been consumed and cached by {@link XssHttpRequestWrapper}.
     */
    private static class CachedBodyServletInputStream extends ServletInputStream {

        private final ByteArrayInputStream inputStream;

        CachedBodyServletInputStream(byte[] body) {
            this.inputStream = new ByteArrayInputStream(body);
        }

        @Override
        public int read() {
            return inputStream.read();
        }

        @Override
        public boolean isFinished() {
            return inputStream.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            // synchronous use only; async reading is not supported
        }
    }
}
