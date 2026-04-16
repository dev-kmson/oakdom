package io.oakdom.xss.rule;

public class WhitelistXssFilterRule implements XssFilterRule {

    @Override
    public String apply(String value) {
        return value;
    }
}
