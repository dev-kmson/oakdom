package io.oakdom.xss.annotation;

import io.oakdom.core.filter.FilterMode;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Overrides the XSS {@link FilterMode} for a controller method or method parameter.
 *
 * <p>When applied to a <strong>method</strong>, the specified filter mode is used
 * for all parameters of that method:
 * <pre>{@code
 * @OakdomXssFilterMode(FilterMode.WHITELIST)
 * @PostMapping("/editor")
 * public ResponseEntity<String> saveContent(@RequestBody String html) {
 *     // 'html' is sanitized with WHITELIST mode
 * }
 * }</pre>
 *
 * <p>When applied to a <strong>parameter</strong>, only that parameter uses the
 * specified filter mode:
 * <pre>{@code
 * @PostMapping("/article")
 * public ResponseEntity<String> saveArticle(
 *         @RequestParam String title,
 *         @OakdomXssFilterMode(FilterMode.WHITELIST) @RequestParam String body) {
 *     // 'title' uses the global/URL filter mode; 'body' uses WHITELIST
 * }
 * }</pre>
 *
 * <p>Parameter-level annotations take precedence over method-level annotations,
 * which in turn take precedence over configuration-based rules.
 *
 * @see OakdomXssExclude
 * @see FilterMode
 */
@Target({ElementType.METHOD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface OakdomXssFilterMode {

    /**
     * The filter mode to apply.
     *
     * @return filter mode; defaults to {@link FilterMode#BLACKLIST}
     */
    FilterMode value() default FilterMode.BLACKLIST;
}
