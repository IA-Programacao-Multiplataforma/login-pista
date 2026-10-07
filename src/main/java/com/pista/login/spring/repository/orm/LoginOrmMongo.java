package com.pista.login.spring.repository.orm;

import com.pista.login.domain.entity.enumerable.Role;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import java.util.*;

@Document(value = "login")
public record LoginOrmMongo(
        @Id String id,
        String username,
        String password,
        String email,
        String cep,
        List<Role> roles
) {
} 