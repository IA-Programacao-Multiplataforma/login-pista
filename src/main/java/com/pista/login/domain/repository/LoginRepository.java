package com.pista.login.domain.repository;
import com.pista.login.domain.entity.User;

public interface LoginRepository {
    User salvar(User user);
    void deletar(String id);

    User findByUsername(String username);
    User findByEmail(String email);

}