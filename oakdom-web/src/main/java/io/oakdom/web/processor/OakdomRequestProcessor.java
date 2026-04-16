package io.oakdom.web.processor;

import io.oakdom.core.filter.FilterMode;

/**
 * Processes request input based on the HTTP {@code Content-Type}.
 *
 * <p>Each implementation handles a specific content type
 * (e.g., JSON, URL-encoded form data, multipart form data).
 */
public interface OakdomRequestProcessor {

    /**
     * Returns {@code true} if this processor can handle the given content type.
     *
     * @param contentType the {@code Content-Type} header value
     * @return {@code true} if this processor supports the content type
     */
    boolean supports(String contentType);

    /**
     * Processes the given input value using the specified {@link FilterMode}.
     *
     * @param value      the raw input value
     * @param filterMode the filter mode to apply
     * @return the processed value
     */
    String process(String value, FilterMode filterMode);
}
