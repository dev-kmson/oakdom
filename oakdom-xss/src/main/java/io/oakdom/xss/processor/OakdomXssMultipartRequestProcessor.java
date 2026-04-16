package io.oakdom.xss.processor;

import io.oakdom.web.processor.OakdomRequestProcessor;

public class OakdomXssMultipartRequestProcessor implements OakdomRequestProcessor {

    @Override
    public boolean supports(String contentType) {
        return false;
    }
}
