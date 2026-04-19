package io.oakdom.xss.interceptor;

/**
 * Request attribute keys used to pass annotation-derived XSS filter settings
 * from {@link OakdomXssAnnotationInterceptor} to
 * {@link io.oakdom.xss.filter.OakdomXssFilter}.
 *
 * <p>These attributes are set by the interceptor during {@code preHandle()} and
 * read by the filter wrapper when request parameters and body are accessed.
 */
public final class OakdomXssRequestAttributes {

    /**
     * Set to {@link Boolean#TRUE} when {@code @OakdomXssExclude} is placed on
     * the handler method. Causes all parameters and the request body to bypass
     * XSS filtering.
     */
    public static final String EXCLUDE_ALL = "oakdom.xss.exclude.all";

    /**
     * Set to a {@link io.oakdom.core.filter.FilterMode} value when
     * {@code @OakdomXssFilterMode} is placed on the handler method. Applied to
     * all parameters and the request body unless overridden by a parameter-level
     * annotation.
     */
    public static final String METHOD_MODE = "oakdom.xss.method.mode";

    /**
     * Prefix for per-parameter exclude flags set by {@code @OakdomXssExclude}
     * on a {@code @RequestParam} parameter. The full attribute key is this prefix
     * concatenated with the HTTP parameter name.
     */
    public static final String PARAM_EXCLUDE_PREFIX = "oakdom.xss.param.exclude.";

    /**
     * Prefix for per-parameter mode overrides set by {@code @OakdomXssFilterMode}
     * on a {@code @RequestParam} parameter. The full attribute key is this prefix
     * concatenated with the HTTP parameter name.
     */
    public static final String PARAM_MODE_PREFIX = "oakdom.xss.param.mode.";

    /**
     * Set to {@link Boolean#TRUE} when {@code @OakdomXssExclude} is placed on
     * a {@code @RequestBody} parameter. Causes the JSON request body to bypass
     * XSS filtering.
     */
    public static final String BODY_EXCLUDE = "oakdom.xss.body.exclude";

    /**
     * Set to a {@link io.oakdom.core.filter.FilterMode} value when
     * {@code @OakdomXssFilterMode} is placed on a {@code @RequestBody} parameter.
     * Applied to the entire JSON request body.
     */
    public static final String BODY_MODE = "oakdom.xss.body.mode";

    /**
     * Set to the {@link Class} of the {@code @RequestBody} parameter so the XSS
     * filter can read DTO field-level annotations ({@code @OakdomXssExclude},
     * {@code @OakdomXssFilterMode}) during JSON body sanitization.
     */
    public static final String BODY_DTO_CLASS = "oakdom.xss.body.dto.class";

    private OakdomXssRequestAttributes() {}
}
