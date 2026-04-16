package io.oakdom.xss.filter;

import io.oakdom.web.filter.VulnerabilityFilter;

public class XssFilter implements VulnerabilityFilter {

    @Override
    public boolean shouldSkip(String requestUri, String contentType) {
        return false;
    }
}
