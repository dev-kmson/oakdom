package io.oakdom.xss.processor;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.core.resolver.ContentTypeResolver;
import io.oakdom.web.processor.OakdomRequestProcessor;
import io.oakdom.xss.sanitizer.DefaultXssSanitizer;
import io.oakdom.xss.sanitizer.XssSanitizer;

/**
 * {@link OakdomRequestProcessor} for {@code application/x-www-form-urlencoded} requests.
 *
 * <p>Handles standard HTML form submissions. Each parameter value is sanitized
 * individually using the configured {@link XssSanitizer}.
 *
 * <p>The no-arg constructor uses the default (uncustomized) sanitizers. When XSS
 * configuration customizations are needed, use
 * {@link #OakdomXssFormRequestProcessor(XssSanitizer, XssSanitizer)} and pass
 * sanitizers obtained from {@link DefaultXssSanitizer#of(FilterMode, io.oakdom.xss.config.XssConfig)}.
 */
public class OakdomXssFormRequestProcessor implements OakdomRequestProcessor {

    private final XssSanitizer blacklistSanitizer;
    private final XssSanitizer whitelistSanitizer;

    /**
     * Creates a processor using the default (uncustomized) sanitizers.
     */
    public OakdomXssFormRequestProcessor() {
        this(DefaultXssSanitizer.of(FilterMode.BLACKLIST), DefaultXssSanitizer.of(FilterMode.WHITELIST));
    }

    /**
     * Creates a processor using the given sanitizers.
     *
     * @param blacklistSanitizer sanitizer applied when the filter mode is {@link FilterMode#BLACKLIST}; must not be {@code null}
     * @param whitelistSanitizer sanitizer applied when the filter mode is {@link FilterMode#WHITELIST}; must not be {@code null}
     */
    public OakdomXssFormRequestProcessor(XssSanitizer blacklistSanitizer, XssSanitizer whitelistSanitizer) {
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
     * Returns {@code true} if the given content type represents URL-encoded form data.
     *
     * @param contentType the {@code Content-Type} header value
     * @return {@code true} if this processor supports the content type
     */
    @Override
    public boolean supports(String contentType) {
        return ContentTypeResolver.isFormUrlEncoded(contentType);
    }

    /**
     * Sanitizes the given form parameter value using the sanitizer for the specified
     * {@link FilterMode}.
     *
     * @param value      the raw parameter value; may be {@code null}
     * @param filterMode the filter mode to apply; must not be {@code null}
     * @return the sanitized value, or {@code null} if {@code value} is {@code null}
     */
    @Override
    public String process(String value, FilterMode filterMode) {
        return (filterMode == FilterMode.WHITELIST ? whitelistSanitizer : blacklistSanitizer).sanitize(value);
    }
}
