package io.oakdom.xss.processor;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.core.resolver.ContentTypeResolver;
import io.oakdom.web.processor.OakdomRequestProcessor;
import io.oakdom.xss.sanitizer.DefaultXssSanitizer;
import io.oakdom.xss.sanitizer.XssSanitizer;

/**
 * {@link OakdomRequestProcessor} for {@code multipart/form-data} requests.
 *
 * <p>Handles multipart form submissions (e.g., forms containing file uploads).
 * Only text-type parts are sanitized; binary parts (file data) are not processed
 * by this class and must be excluded from sanitization at the filter level.
 *
 * <p>The no-arg constructor uses the default (uncustomized) sanitizers. When XSS
 * configuration customizations are needed, use
 * {@link #OakdomXssMultipartRequestProcessor(XssSanitizer, XssSanitizer)} and pass
 * sanitizers obtained from {@link DefaultXssSanitizer#of(FilterMode, io.oakdom.xss.config.XssConfig)}.
 */
public class OakdomXssMultipartRequestProcessor implements OakdomRequestProcessor {

    private final XssSanitizer blacklistSanitizer;
    private final XssSanitizer whitelistSanitizer;

    /**
     * Creates a processor using the default (uncustomized) sanitizers.
     */
    public OakdomXssMultipartRequestProcessor() {
        this(DefaultXssSanitizer.of(FilterMode.BLACKLIST), DefaultXssSanitizer.of(FilterMode.WHITELIST));
    }

    /**
     * Creates a processor using the given sanitizers.
     *
     * @param blacklistSanitizer sanitizer applied when the filter mode is {@link FilterMode#BLACKLIST}; must not be {@code null}
     * @param whitelistSanitizer sanitizer applied when the filter mode is {@link FilterMode#WHITELIST}; must not be {@code null}
     */
    public OakdomXssMultipartRequestProcessor(XssSanitizer blacklistSanitizer, XssSanitizer whitelistSanitizer) {
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
     * Returns {@code true} if the given content type represents multipart form data.
     *
     * @param contentType the {@code Content-Type} header value
     * @return {@code true} if this processor supports the content type
     */
    @Override
    public boolean supports(String contentType) {
        return ContentTypeResolver.isMultipart(contentType);
    }

    /**
     * Sanitizes the given multipart text field value using the sanitizer for the specified
     * {@link FilterMode}.
     *
     * <p>This method is intended to be called only for text-type parts. Binary parts
     * (e.g., uploaded file contents) must be excluded from processing at the filter level.
     *
     * @param value      the raw text field value; may be {@code null}
     * @param filterMode the filter mode to apply; must not be {@code null}
     * @return the sanitized value, or {@code null} if {@code value} is {@code null}
     */
    @Override
    public String process(String value, FilterMode filterMode) {
        return (filterMode == FilterMode.WHITELIST ? whitelistSanitizer : blacklistSanitizer).sanitize(value);
    }
}
