package io.oakdom.web.processor;

import io.oakdom.core.filter.FilterMode;

public interface OakdomRequestProcessor {

    boolean supports(String contentType);

    String process(String value, FilterMode filterMode);
}
