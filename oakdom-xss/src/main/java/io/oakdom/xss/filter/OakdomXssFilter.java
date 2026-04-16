package io.oakdom.xss.filter;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.web.filter.OakdomFilter;

public class OakdomXssFilter implements OakdomFilter {

    @Override
    public boolean shouldSkip(String requestUri, String parameterName) {
        return false;
    }

    @Override
    public FilterMode resolveFilterMode(String requestUri, String parameterName) {
        return FilterMode.BLACKLIST;
    }
}
