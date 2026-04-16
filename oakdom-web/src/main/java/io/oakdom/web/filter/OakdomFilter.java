package io.oakdom.web.filter;

import io.oakdom.core.filter.FilterMode;

public interface OakdomFilter {

    boolean shouldSkip(String requestUri, String parameterName);

    FilterMode resolveFilterMode(String requestUri, String parameterName);
}
