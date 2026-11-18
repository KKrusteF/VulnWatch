package com.vulnwatch.web;

import com.vulnwatch.cve.Severity;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

import java.util.Locale;

/**
 * Lets request parameters use any letter case, e.g. {@code ?severity=critical}.
 * Spring Boot registers every {@code Converter} bean with Spring MVC automatically.
 */
@Component
public class StringToSeverityConverter implements Converter<String, Severity> {

    @Override
    public Severity convert(String source) {
        return Severity.valueOf(source.trim().toUpperCase(Locale.ROOT));
    }
}
