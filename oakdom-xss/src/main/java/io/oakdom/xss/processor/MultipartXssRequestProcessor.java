package io.oakdom.xss.processor;

import io.oakdom.web.processor.RequestProcessor;

public class MultipartXssRequestProcessor implements RequestProcessor {

    @Override
    public boolean supports(String contentType) {
        return false;
    }
}
