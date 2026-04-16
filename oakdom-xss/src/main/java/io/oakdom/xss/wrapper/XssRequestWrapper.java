package io.oakdom.xss.wrapper;

import io.oakdom.web.wrapper.VulnerabilityRequestWrapper;

public class XssRequestWrapper extends VulnerabilityRequestWrapper {

    @Override
    public String sanitizeValue(String value) {
        return value;
    }
}
