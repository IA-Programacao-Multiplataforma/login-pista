package com.pista.login;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.ImportRuntimeHints;
import com.pista.login.spring.config.JwtNativeHints;

@SpringBootApplication
@ImportRuntimeHints(JwtNativeHints.class)
public class LoginApplication {
	public static void main(String[] args) {
		SpringApplication.run(LoginApplication.class, args);
	}
}
