package com.pista.login.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.pista.login.domain.entity.User;
import com.pista.login.domain.entity.enumerable.Role;
import com.pista.login.spring.security.dto.AuthUserDetails;

import jakarta.servlet.http.Cookie;

class JwtAuthFilterSecurityTest {

    private final JwtSecurity jwt = new JwtSecurity("segredo-de-teste-com-32-caracteres!");
    private final UserDetailsService usuarios = mock(UserDetailsService.class);
    private final JwtAuthFilterSecurity filtro = new JwtAuthFilterSecurity(jwt, usuarios);

    private final AuthUserDetails ana = new AuthUserDetails(
            new User("1", "ana", "hash", "ana@teste.com", "01001000", List.of(Role.USER)));

    private MockHttpServletRequest requisicao;
    private MockFilterChain cadeia;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        requisicao = new MockHttpServletRequest("GET", "/autenticacao/v1/me");
        requisicao.setServletPath("/autenticacao/v1/me");
        cadeia = new MockFilterChain();
        when(usuarios.loadUserByUsername("ana@teste.com")).thenReturn(ana);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private void executar() throws Exception {
        filtro.doFilter(requisicao, new MockHttpServletResponse(), cadeia);
    }

    private boolean autenticado() {
        return SecurityContextHolder.getContext().getAuthentication() != null;
    }

    @Test
    void tokenNoHeaderBearerAutenticaOUsuario() throws Exception {
        requisicao.addHeader("Authorization", "Bearer " + jwt.generateToken(ana));

        executar();

        assertThat(autenticado()).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("ana@teste.com");
        assertThat(cadeia.getRequest()).isNotNull();
    }

    @Test
    void tokenNoCookieTambemAutentica() throws Exception {
        requisicao.setCookies(new Cookie("access_token", jwt.generateToken(ana)));

        executar();

        assertThat(autenticado()).isTrue();
    }

    @Test
    void semTokenSegueSemAutenticar() throws Exception {
        executar();

        assertThat(autenticado()).isFalse();
        assertThat(cadeia.getRequest()).isNotNull();
    }

    @Test
    void tokenAdulteradoSegueSemAutenticar() throws Exception {
        requisicao.addHeader("Authorization", "Bearer " + jwt.generateToken(ana) + "x");

        executar();

        assertThat(autenticado()).isFalse();
        assertThat(cadeia.getRequest()).isNotNull();
    }

    @Test
    void lixoNoHeaderSegueSemAutenticar() throws Exception {
        requisicao.addHeader("Authorization", "Bearer isso-nao-e-jwt");

        executar();

        assertThat(autenticado()).isFalse();
    }

    @Test
    void headerSemBearerEhIgnorado() throws Exception {
        requisicao.addHeader("Authorization", jwt.generateToken(ana));

        executar();

        assertThat(autenticado()).isFalse();
    }

    @Test
    void tokenDeUsuarioQueNaoExisteMaisNaoAutentica() throws Exception {
        String token = jwt.generateToken(ana);
        when(usuarios.loadUserByUsername("ana@teste.com")).thenThrow(new UsernameNotFoundException("sumiu"));
        requisicao.addHeader("Authorization", "Bearer " + token);

        executar();

        assertThat(autenticado()).isFalse();
    }

    @Test
    void loginECadastroNaoPassamPeloFiltro() throws Exception {
        for (String caminho : List.of("/autenticacao/v1/login", "/autenticacao/v1/create")) {
            cadeia = new MockFilterChain();
            requisicao = new MockHttpServletRequest("POST", caminho);
            requisicao.setServletPath(caminho);
            requisicao.addHeader("Authorization", "Bearer token-velho");

            executar();
        }

        verify(usuarios, never()).loadUserByUsername(any());
        assertThat(autenticado()).isFalse();
    }
}
