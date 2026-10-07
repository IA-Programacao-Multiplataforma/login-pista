package com.pista.login.spring.controller.dto.response;

import com.pista.login.domain.entity.enumerable.Role;
import java.util.List;  
public record UserResponse(
        String id,
        String username,
        String email,
        String cep,
        List<Role> roles
    ) {
    
}