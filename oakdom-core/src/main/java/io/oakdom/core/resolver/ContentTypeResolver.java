package io.oakdom.core.resolver;

public class ContentTypeResolver {

    public boolean isJson(String contentType) {
        return false;
    }

    public boolean isFormUrlEncoded(String contentType) {
        return false;
    }

    public boolean isMultipart(String contentType) {
        return false;
    }
}
