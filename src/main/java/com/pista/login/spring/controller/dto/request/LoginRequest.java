package com.pista.login.spring.controller.dto.request;

public record LoginRequest(
    String email,
    String password
) {

}