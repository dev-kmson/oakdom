package io.oakdom.xss.filter;

import io.oakdom.web.filter.OakdomFilter;

public class OakdomXssFilter implements OakdomFilter {

    @Override
    public boolean shouldSkip(String requestUri, String contentType) {
        return false;
    }
}
