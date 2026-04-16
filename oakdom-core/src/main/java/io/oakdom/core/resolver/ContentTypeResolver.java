package io.oakdom.core.resolver;

public final class ContentTypeResolver {

    private ContentTypeResolver() {}

    public static boolean isJson(String contentType) {
        return false;
    }

    public static boolean isFormUrlEncoded(String contentType) {
        return false;
    }

    public static boolean isMultipart(String contentType) {
        return false;
    }
}
