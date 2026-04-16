# oakdom

A lightweight open-source library for defending against input-based web security vulnerabilities in Java/Spring environments.

oakdom covers what Spring Security does not: input sanitization for XSS, SQL injection, CRLF, and similar threats. Add one dependency and it works.

## Supported Environments

- JDK 1.8+
- Plain Servlet
- Spring Boot 2.x
- Spring Boot 3.x

## Quick Start

**Spring Boot 2.x**
```xml
<dependency>
    <groupId>io.oakdom</groupId>
    <artifactId>oakdom-xss-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

**Spring Boot 3.x**
```xml
<dependency>
    <groupId>io.oakdom</groupId>
    <artifactId>oakdom-xss-spring-boot3-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

**Plain Servlet**
```xml
<dependency>
    <groupId>io.oakdom</groupId>
    <artifactId>oakdom-xss</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Configuration

```properties
# Enable/disable XSS filter (default: true)
oakdom.xss.enabled=true

# Filter mode: blacklist or whitelist
oakdom.xss.filter-mode=blacklist

# URLs to exclude from filtering
oakdom.xss.exclude-urls=/api/editor/**, /admin/**

# Parameters to exclude from filtering
oakdom.xss.exclude-parameters=htmlContent, rawData
```

## Modules

| Module | Description |
|--------|-------------|
| `oakdom-core` | Pure Java common interfaces |
| `oakdom-web` | Servlet-based common interfaces |
| `oakdom-xss` | XSS sanitization and servlet filter |
| `oakdom-xss-spring-boot-starter` | Auto-configuration for Spring Boot 2.x |
| `oakdom-xss-spring-boot3-starter` | Auto-configuration for Spring Boot 3.x |
| `oakdom-all-spring-boot-starter` | All-in-one starter for Spring Boot 2.x |
| `oakdom-all-spring-boot3-starter` | All-in-one starter for Spring Boot 3.x |

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
