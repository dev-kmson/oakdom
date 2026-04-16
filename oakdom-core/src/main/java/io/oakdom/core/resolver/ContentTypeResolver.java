package io.oakdom.core.resolver;

/**
 * Utility class for determining the content type of an HTTP request.
 *
 * <p>Used to select the appropriate {@code OakdomRequestProcessor} based on
 * the {@code Content-Type} header value.
 */
public final class ContentTypeResolver {

    private static final String APPLICATION_JSON = "application/json";
    private static final String APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded";
    private static final String MULTIPART_FORM_DATA = "multipart/form-data";

    private ContentTypeResolver() {}

    /**
     * Returns {@code true} if the given content type represents JSON.
     *
     * @param contentType the {@code Content-Type} header value
     * @return {@code true} if the content type is {@code application/json}
     */
    public static boolean isJson(String contentType) {
        return contentType != null && contentType.toLowerCase().contains(APPLICATION_JSON);
    }

    /**
     * Returns {@code true} if the given content type represents URL-encoded form data.
     *
     * @param contentType the {@code Content-Type} header value
     * @return {@code true} if the content type is {@code application/x-www-form-urlencoded}
     */
    public static boolean isFormUrlEncoded(String contentType) {
        return contentType != null && contentType.toLowerCase().contains(APPLICATION_FORM_URLENCODED);
    }

    /**
     * Returns {@code true} if the given content type represents multipart form data.
     *
     * @param contentType the {@code Content-Type} header value
     * @return {@code true} if the content type is {@code multipart/form-data}
     */
    public static boolean isMultipart(String contentType) {
        return contentType != null && contentType.toLowerCase().contains(MULTIPART_FORM_DATA);
    }
}
