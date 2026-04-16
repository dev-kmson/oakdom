package io.oakdom.xss.rule;

public class BlacklistXssFilterRule implements XssFilterRule {

    @Override
    public String apply(String value) {
        return value;
    }
}
