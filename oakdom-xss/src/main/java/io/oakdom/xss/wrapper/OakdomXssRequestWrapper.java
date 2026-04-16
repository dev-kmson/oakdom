package io.oakdom.xss.wrapper;

import io.oakdom.web.wrapper.OakdomRequestWrapper;

public class OakdomXssRequestWrapper extends OakdomRequestWrapper {

    @Override
    public String sanitizeValue(String value) {
        return value;
    }
}
