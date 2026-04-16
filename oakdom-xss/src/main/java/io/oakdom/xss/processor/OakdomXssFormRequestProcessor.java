package io.oakdom.xss.processor;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.core.resolver.ContentTypeResolver;
import io.oakdom.web.processor.OakdomRequestProcessor;
import io.oakdom.xss.sanitizer.DefaultXssSanitizer;

/**
 * {@link OakdomRequestProcessor} for {@code application/x-www-form-urlencoded} requests.
 *
 * <p>Handles standard HTML form submissions. Each parameter value is sanitized
 * individually using {@link DefaultXssSanitizer}.
 */
public class OakdomXssFormRequestProcessor implements OakdomRequestProcessor {

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
     * Sanitizes the given form parameter value using the specified {@link FilterMode}.
     *
     * @param value      the raw parameter value; may be {@code null}
     * @param filterMode the filter mode to apply; must not be {@code null}
     * @return the sanitized value, or {@code null} if {@code value} is {@code null}
     */
    @Override
    public String process(String value, FilterMode filterMode) {
        return DefaultXssSanitizer.of(filterMode).sanitize(value);
    }
}
