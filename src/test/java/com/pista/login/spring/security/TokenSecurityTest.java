package com.pista.login.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.pista.login.domain.entity.Login;
import com.pista.login.domain.entity.Token;
import com.pista.login.domain.entity.User;
import com.pista.login.domain.entity.enumerable.Role;
import com.pista.login.spring.security.dto.AuthUserDetails;

class TokenSecurityTest {

    private final AuthenticationManager manager = mock(AuthenticationManager.class);
    private final UserDetailsService detalhes = mock(UserDetailsService.class);
    private final JwtSecurity jwt = new JwtSecurity("segredo-de-teste-com-32-caracteres!");
    private final TokenSecurity tokenSecurity = new TokenSecurity(jwt, detalhes, manager);

    @Test
    void credenciaisCorretasGeramTokenDoUsuario() {
        when(detalhes.loadUserByUsername("ana@teste.com"))
                .thenReturn(new AuthUserDetails(new User("1", "ana", "hash", "ana@teste.com", "01001000", List.of(Role.USER))));

        Token token = tokenSecurity.gerarToken(new Login("ana@teste.com", "senha123"));

        assertThat(jwt.getUsername(token.value())).isEqualTo("ana@teste.com");
        verify(manager).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    void senhaErradaNaoGeraToken() {
        when(manager.authenticate(any())).thenThrow(new BadCredentialsException("senha errada"));

        assertThatThrownBy(() -> tokenSecurity.gerarToken(new Login("ana@teste.com", "errada")))
                .isInstanceOf(BadCredentialsException.class);
        verify(detalhes, never()).loadUserByUsername(any());
    }
}
