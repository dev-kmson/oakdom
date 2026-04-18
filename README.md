# oakdom

> **⚠️ This project is currently under active development and is not yet available for production use.**

A lightweight open-source library for defending against input-based web security vulnerabilities in Java/Spring environments.

oakdom covers what Spring Security does not: input sanitization for XSS, SQL injection, CRLF, and similar threats. Add one dependency and it works.

## Supported Environments

- JDK 1.8+
- Legacy Spring MVC
- Spring Boot 2.x
- Spring Boot 3.x

## Modules

| Module | Description | Docs |
|--------|-------------|------|
| `oakdom-xss` | XSS sanitization for legacy Spring MVC / servlet environments (`javax.servlet`, Tomcat 9 or below) | [README](oakdom-xss/README.md) |
| `oakdom-xss-jakarta` | XSS sanitization for legacy Spring MVC / servlet environments (`jakarta.servlet`, Tomcat 10.1+, JDK 11+) | [README](oakdom-xss-jakarta/README.md) |
| `oakdom-xss-spring-boot-starter` | Auto-configured XSS filter for Spring Boot 2.x | [README](oakdom-xss-spring-boot-starter/README.md) |
| `oakdom-xss-spring-boot3-starter` | Auto-configured XSS filter for Spring Boot 3.x | [README](oakdom-xss-spring-boot3-starter/README.md) |

## Which Module Should I Use?

| Environment | Dependency |
|-------------|------------|
| Legacy Spring MVC / servlet, Tomcat 9 or below (`javax.servlet`, JDK 1.8+) | `oakdom-xss` |
| Legacy Spring MVC / servlet, Tomcat 10.1+ (`jakarta.servlet`, JDK 11+) | `oakdom-xss-jakarta` |
| Spring Boot 2.x | `oakdom-xss-spring-boot-starter` |
| Spring Boot 3.x | `oakdom-xss-spring-boot3-starter` |

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
