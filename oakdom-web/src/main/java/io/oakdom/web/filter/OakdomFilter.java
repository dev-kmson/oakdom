package io.oakdom.web.filter;

public interface OakdomFilter {

    boolean shouldSkip(String requestUri, String contentType);
}
