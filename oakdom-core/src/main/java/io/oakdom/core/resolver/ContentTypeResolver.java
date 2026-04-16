package io.oakdom.core.resolver;

public final class ContentTypeResolver {

    private static final String APPLICATION_JSON = "application/json";
    private static final String APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded";
    private static final String MULTIPART_FORM_DATA = "multipart/form-data";

    private ContentTypeResolver() {}

    public static boolean isJson(String contentType) {
        return contentType != null && contentType.toLowerCase().contains(APPLICATION_JSON);
    }

    public static boolean isFormUrlEncoded(String contentType) {
        return contentType != null && contentType.toLowerCase().contains(APPLICATION_FORM_URLENCODED);
    }

    public static boolean isMultipart(String contentType) {
        return contentType != null && contentType.toLowerCase().contains(MULTIPART_FORM_DATA);
    }
}
