# oakdom

> **⚠️ This project is currently under active development and is not yet available for production use.**

A lightweight open-source library for defending against input-based web security vulnerabilities in Java/Spring environments.

oakdom covers what Spring Security does not: input sanitization for XSS, SQL injection, CRLF, and similar threats. Add one dependency and it works.

## Supported Environments

- JDK 1.8+
- Plain Servlet
- Spring Boot 2.x
- Spring Boot 3.x

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
