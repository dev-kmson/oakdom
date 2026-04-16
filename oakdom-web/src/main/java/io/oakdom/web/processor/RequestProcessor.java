package io.oakdom.web.processor;

public interface RequestProcessor {

    boolean supports(String contentType);
}
