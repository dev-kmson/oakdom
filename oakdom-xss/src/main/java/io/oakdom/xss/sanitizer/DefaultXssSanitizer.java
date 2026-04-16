package io.oakdom.xss.sanitizer;

public class DefaultXssSanitizer implements XssSanitizer {

    @Override
    public String sanitize(String value) {
        return value;
    }
}
