package io.oakdom.xss.processor;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.core.resolver.ContentTypeResolver;
import io.oakdom.web.processor.OakdomRequestProcessor;
import io.oakdom.xss.sanitizer.DefaultXssSanitizer;

/**
 * {@link OakdomRequestProcessor} for {@code multipart/form-data} requests.
 *
 * <p>Handles multipart form submissions (e.g., forms containing file uploads).
 * Only text-type parts are sanitized; binary parts (file data) are not processed
 * by this class and must be excluded from sanitization at the filter level.
 *
 * <p>Each text part value is sanitized individually using {@link DefaultXssSanitizer}.
 */
public class OakdomXssMultipartRequestProcessor implements OakdomRequestProcessor {

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
     * Sanitizes the given multipart text field value using the specified {@link FilterMode}.
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
        return DefaultXssSanitizer.of(filterMode).sanitize(value);
    }
}
