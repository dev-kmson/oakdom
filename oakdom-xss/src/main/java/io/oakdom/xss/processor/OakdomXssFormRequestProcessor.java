package io.oakdom.xss.processor;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.web.processor.OakdomRequestProcessor;

public class OakdomXssFormRequestProcessor implements OakdomRequestProcessor {

    @Override
    public boolean supports(String contentType) {
        return false;
    }

    @Override
    public String process(String value, FilterMode filterMode) {
        return value;
    }
}
