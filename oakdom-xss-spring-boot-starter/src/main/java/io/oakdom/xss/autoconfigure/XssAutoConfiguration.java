package io.oakdom.xss.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(XssProperties.class)
@ConditionalOnProperty(prefix = "oakdom.xss", name = "enabled", havingValue = "true", matchIfMissing = true)
public class XssAutoConfiguration {
}
