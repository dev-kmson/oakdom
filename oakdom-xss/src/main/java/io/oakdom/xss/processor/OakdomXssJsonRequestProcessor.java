package io.oakdom.xss.processor;

import io.oakdom.web.processor.OakdomRequestProcessor;

public class OakdomXssJsonRequestProcessor implements OakdomRequestProcessor {

    @Override
    public boolean supports(String contentType) {
        return false;
    }
}
