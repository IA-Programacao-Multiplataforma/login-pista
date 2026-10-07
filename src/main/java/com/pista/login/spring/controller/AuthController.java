package com.pista.login.spring.controller;

import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;  
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.pista.login.domain.entity.Login;
import com.pista.login.domain.entity.Token;
import com.pista.login.domain.entity.User;
import com.pista.login.domain.repository.LoginRepository;
import com.pista.login.spring.controller.adapter.AuthControllerAdapter;
import com.pista.login.spring.controller.adapter.UserControllerAdapter;
import com.pista.login.spring.controller.dto.request.LoginRequest;
import com.pista.login.spring.controller.dto.request.UserRequest;
import com.pista.login.spring.controller.dto.response.AuthResponse;
import com.pista.login.spring.controller.dto.response.UserResponse;
import com.pista.login.spring.security.dto.AuthUserDetails;
import com.pista.login.spring.security.TokenSecurity;

import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/autenticacao")
public class AuthController {

    private final TokenSecurity tokenSecurity;
    private final LoginRepository repository;
    private final PasswordEncoder passwordEncoder;

    private static final String ACCESS_TOKEN_COOKIE = "access_token";

    public AuthController(TokenSecurity tokenSecurity, LoginRepository repository, PasswordEncoder passwordEncoder) {
        this.tokenSecurity = tokenSecurity;
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
    }

    private void validarNovoUsuario(UserRequest request) {
        if (isBlank(request.username()) || isBlank(request.password()) || isBlank(request.email())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "username, password e email são obrigatórios");
        }
        if (repository.findByUsername(request.username()) != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username já cadastrado");
        }
        if (repository.findByEmail(request.email().trim().toLowerCase()) != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email já cadastrado");
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    @PostMapping("/v1/login")
    public AuthResponse login(@RequestBody LoginRequest request, HttpServletResponse response) {
        Login login = AuthControllerAdapter.cast(request);
        Token token = tokenSecurity.gerarToken(login);

        ResponseCookie cookie = ResponseCookie.from(ACCESS_TOKEN_COOKIE, token.value())
                .httpOnly(true)
                .secure(false) 
                .sameSite("Lax")
                .path("/")
                .maxAge(3600) 
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return new AuthResponse(token.value());
    }

    @PostMapping("/v1/create")
    public AuthResponse create(@RequestBody UserRequest request, HttpServletResponse response) {
        validarNovoUsuario(request);

        User novo = UserControllerAdapter.cast(request);
        repository.salvar(new User(
                novo.id(),
                novo.username(),
                passwordEncoder.encode(novo.password()),
                novo.email(),
                novo.cep(),
                novo.roles()));

        Login login = new Login(novo.email(), request.password());
        Token token = tokenSecurity.gerarToken(login);

        ResponseCookie cookie = ResponseCookie.from(ACCESS_TOKEN_COOKIE, token.value())
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax") 
                .path("/")
                .maxAge(3600) 
                .build();
        
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        
        return new AuthResponse(token.value());
    }

    @GetMapping("/v1/me")
    public UserResponse me(Authentication authentication) {
        User logado = ((AuthUserDetails) authentication.getPrincipal()).login();
        return UserControllerAdapter.toResponse(logado);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, String>> credenciaisInvalidas(AuthenticationException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("erro", "Usuário ou senha inválidos"));
    }

    @ResponseStatus(HttpStatus.OK)
    @PostMapping("/v1/logout")
    public void logout(HttpServletResponse response) { 
        ResponseCookie cookie = ResponseCookie.from(ACCESS_TOKEN_COOKIE, "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(0) 
                .build();
        
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}