package com.pista.login.spring.config;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * O jjwt cria suas classes por reflexão (Keys, Jwts.builder, Jwts.parser, Jwts.SIG...) e lê arquivos
 * de META-INF/services. No executável nativo (GraalVM) isso precisa ser declarado antes, senão dá
 * "Could not initialize class io.jsonwebtoken.security.Keys". Na hora do build, varre o classpath e
 * registra todas as classes do jjwt (api, impl e jackson).
 */
public class JwtNativeHints implements RuntimeHintsRegistrar {

    @Override
    public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver(classLoader);
        try {
            for (Resource resource : resolver.getResources("classpath*:io/jsonwebtoken/**/*.class")) {
                String path = resource.getURL().toString();
                int start = path.lastIndexOf("io/jsonwebtoken/");
                String name = path.substring(start, path.length() - ".class".length()).replace('/', '.');
                if (name.endsWith("package-info") || name.endsWith("module-info")) {
                    continue;
                }
                hints.reflection().registerType(TypeReference.of(name), MemberCategory.values());
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        hints.resources().registerPattern("META-INF/services/io.jsonwebtoken.*");
    }
}
