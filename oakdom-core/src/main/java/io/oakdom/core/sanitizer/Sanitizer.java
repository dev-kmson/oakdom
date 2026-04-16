package io.oakdom.core.sanitizer;

/**
 * Top-level contract for all sanitization implementations in oakdom.
 *
 * <p>All vulnerability-specific sanitizers (e.g., XSS, SQL) extend this interface
 * and provide their own sanitization logic.
 */
public interface Sanitizer {

    /**
     * Sanitizes the given input value.
     *
     * @param value the raw input value to sanitize
     * @return the sanitized value
     */
    String sanitize(String value);
}
