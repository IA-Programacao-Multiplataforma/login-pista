package com.pista.login.domain.entity;

import java.util.List;
import com.pista.login.domain.entity.enumerable.Role;

public record User(
        String id,
        String username,
        String password,
        String email,
        String cep,
        List<Role> roles
){
    
}