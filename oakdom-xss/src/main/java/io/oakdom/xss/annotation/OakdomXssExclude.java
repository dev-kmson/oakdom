package io.oakdom.xss.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a controller method or method parameter as excluded from XSS filtering.
 *
 * <p>When applied to a <strong>method</strong>, all parameters of that method
 * bypass XSS sanitization:
 * <pre>{@code
 * @OakdomXssExclude
 * @PostMapping("/raw")
 * public ResponseEntity<String> uploadRaw(@RequestBody String content) {
 *     // 'content' is not XSS-filtered
 * }
 * }</pre>
 *
 * <p>When applied to a <strong>parameter</strong>, only that parameter bypasses
 * XSS sanitization:
 * <pre>{@code
 * @PostMapping("/article")
 * public ResponseEntity<String> saveArticle(
 *         @RequestParam String title,
 *         @OakdomXssExclude @RequestParam String rawHtml) {
 *     // 'title' is XSS-filtered; 'rawHtml' is not
 * }
 * }</pre>
 *
 * @see OakdomXssFilterMode
 */
@Target({ElementType.METHOD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface OakdomXssExclude {
}
