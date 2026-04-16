package io.oakdom.core.rule;

/**
 * Defines a single filtering rule applied during sanitization.
 *
 * <p>Implementations provide specific rule logic such as blacklist pattern matching
 * or whitelist tag allowance.
 */
public interface FilterRule {

    /**
     * Applies this rule to the given input value.
     *
     * @param value the input value to process
     * @return the value after applying this rule
     */
    String apply(String value);
}
