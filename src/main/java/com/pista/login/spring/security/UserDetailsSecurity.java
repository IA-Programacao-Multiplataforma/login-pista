package com.pista.login.spring.security;

import com.pista.login.domain.entity.User;
import com.pista.login.domain.repository.LoginRepository;
import com.pista.login.spring.security.dto.AuthUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class UserDetailsSecurity implements UserDetailsService {

    private final LoginRepository repository;

    public UserDetailsSecurity(LoginRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User login = repository.findByEmail(username);

        if (login == null) {
            System.out.println(">>> ERRO: USUÁRIO " + username + " NÃO EXISTE NO BANCO! <<<");
            throw new UsernameNotFoundException("Usuário não encontrado");
        }

        return new AuthUserDetails(login);
    }
}