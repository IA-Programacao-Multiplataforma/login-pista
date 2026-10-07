package com.pista.login.spring.controller.adapter;

import java.util.List;
import java.util.UUID;

import com.pista.login.spring.controller.dto.request.UserRequest;
import com.pista.login.spring.controller.dto.response.UserResponse;
import com.pista.login.domain.entity.User;
import com.pista.login.domain.entity.enumerable.Role;

public class UserControllerAdapter {

    private UserControllerAdapter() {}

    public static User cast(UserRequest request) {
        return new User(
                UUID.randomUUID().toString(),
                request.username(),
                request.password(),
                request.email().trim().toLowerCase(),
                request.cep(),
                List.of(Role.USER)
        );
    }

    public static UserResponse toResponse(User user) {
        return new UserResponse(
                user.id(),
                user.username(),
                user.email(),
                user.cep(),
                user.roles()
        );
    }

    public static User castPutRequest(UserRequest request) {
        return new User(
                request.id(), 
                request.username(),
                request.password(),
                request.email(),
                request.cep(),
                request.roles()
        );
    }
}