package com.pista.login.spring.controller.adapter;

import com.pista.login.spring.controller.dto.request.LoginRequest;
import com.pista.login.domain.entity.Login;

public class AuthControllerAdapter {
    private AuthControllerAdapter() {}

    public static Login cast(LoginRequest request) {
        String email = request.email() == null ? null : request.email().trim().toLowerCase();
        return new Login(email, request.password());
    }
}