package com.pista.login.spring.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.pista.login.domain.entity.Login;
import com.pista.login.domain.entity.Token;
import com.pista.login.domain.entity.User;
import com.pista.login.domain.entity.enumerable.Role;
import com.pista.login.domain.repository.LoginRepository;
import com.pista.login.spring.security.TokenSecurity;
import com.pista.login.spring.security.dto.AuthUserDetails;

class AuthControllerTest {

    private final TokenSecurity tokenSecurity = mock(TokenSecurity.class);
    private final LoginRepository repository = mock(LoginRepository.class);
    private final PasswordEncoder encoder = new BCryptPasswordEncoder();

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.standaloneSetup(new AuthController(tokenSecurity, repository, encoder)).build();
        when(tokenSecurity.gerarToken(any(Login.class))).thenReturn(new Token("jwt-de-teste"));
    }

    private static String cadastro(String username, String email, String senha) {
        return """
                {"username":%s,"email":%s,"password":%s,"cep":"01001000"}
                """.formatted(quote(username), quote(email), quote(senha));
    }

    private static String quote(String valor) {
        return valor == null ? "null" : "\"" + valor + "\"";
    }

    @Test
    void cadastroCriaUsuarioEDevolveToken() throws Exception {
        mvc.perform(post("/autenticacao/v1/create").contentType(MediaType.APPLICATION_JSON)
                        .content(cadastro("ana", "ana@teste.com", "senha123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-de-teste"))
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("access_token=jwt-de-teste")))
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("HttpOnly")));

        ArgumentCaptor<User> salvo = ArgumentCaptor.forClass(User.class);
        verify(repository).salvar(salvo.capture());
        org.assertj.core.api.Assertions.assertThat(salvo.getValue().password()).isNotEqualTo("senha123");
        org.assertj.core.api.Assertions.assertThat(encoder.matches("senha123", salvo.getValue().password())).isTrue();
    }

    @Test
    void cadastroGuardaOEmailEmMinusculasESemEspacos() throws Exception {
        mvc.perform(post("/autenticacao/v1/create").contentType(MediaType.APPLICATION_JSON)
                        .content(cadastro("ana", "  Ana@Teste.COM ", "senha123")))
                .andExpect(status().isOk());

        ArgumentCaptor<User> salvo = ArgumentCaptor.forClass(User.class);
        verify(repository).salvar(salvo.capture());
        org.assertj.core.api.Assertions.assertThat(salvo.getValue().email()).isEqualTo("ana@teste.com");
    }

    @Test
    void cadastroNuncaDaPapelDeAdmin() throws Exception {
        String malicioso = """
                {"username":"hacker","email":"h@teste.com","password":"senha123","cep":"01001000","roles":["ADMIN"]}
                """;

        mvc.perform(post("/autenticacao/v1/create").contentType(MediaType.APPLICATION_JSON).content(malicioso))
                .andExpect(status().isOk());

        ArgumentCaptor<User> salvo = ArgumentCaptor.forClass(User.class);
        verify(repository).salvar(salvo.capture());
        org.assertj.core.api.Assertions.assertThat(salvo.getValue().roles()).containsExactly(Role.USER);
    }

    @Test
    void cadastroSemCamposObrigatoriosDa400() throws Exception {
        mvc.perform(post("/autenticacao/v1/create").contentType(MediaType.APPLICATION_JSON)
                        .content(cadastro("ana", "ana@teste.com", null)))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/autenticacao/v1/create").contentType(MediaType.APPLICATION_JSON)
                        .content(cadastro(" ", "ana@teste.com", "senha123")))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/autenticacao/v1/create").contentType(MediaType.APPLICATION_JSON)
                        .content(cadastro("ana", "", "senha123")))
                .andExpect(status().isBadRequest());

        verify(repository, never()).salvar(any());
    }

    @Test
    void cadastroComUsernameRepetidoDa409() throws Exception {
        when(repository.findByUsername("ana")).thenReturn(
                new User("1", "ana", "hash", "outra@teste.com", "01001000", List.of(Role.USER)));

        mvc.perform(post("/autenticacao/v1/create").contentType(MediaType.APPLICATION_JSON)
                        .content(cadastro("ana", "ana@teste.com", "senha123")))
                .andExpect(status().isConflict());

        verify(repository, never()).salvar(any());
    }

    @Test
    void cadastroComEmailRepetidoDa409MesmoComOutraCaixa() throws Exception {
        when(repository.findByEmail("ana@teste.com")).thenReturn(
                new User("1", "outro", "hash", "ana@teste.com", "01001000", List.of(Role.USER)));

        mvc.perform(post("/autenticacao/v1/create").contentType(MediaType.APPLICATION_JSON)
                        .content(cadastro("ana", "ANA@teste.com", "senha123")))
                .andExpect(status().isConflict());

        verify(repository, never()).salvar(any());
    }

    @Test
    void loginComCredenciaisCertasDevolveTokenECookie() throws Exception {
        mvc.perform(post("/autenticacao/v1/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"ana@teste.com\",\"password\":\"senha123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-de-teste"))
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("Max-Age=3600")));
    }

    @Test
    void loginComSenhaErradaDa401SemRevelarQualCampoErrou() throws Exception {
        when(tokenSecurity.gerarToken(any(Login.class))).thenThrow(new BadCredentialsException("senha errada"));

        mvc.perform(post("/autenticacao/v1/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"ana@teste.com\",\"password\":\"errada\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.erro").value("Usuário ou senha inválidos"));
    }

    @Test
    void logoutLimpaOCookie() throws Exception {
        mvc.perform(post("/autenticacao/v1/logout"))
                .andExpect(status().isOk())
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("Max-Age=0")));
    }

    @Test
    void meDevolveOUsuarioLogadoSemASenha() throws Exception {
        User ana = new User("1", "ana", "hash-secreto", "ana@teste.com", "01001000", List.of(Role.USER));
        var auth = new UsernamePasswordAuthenticationToken(new AuthUserDetails(ana), null);

        mvc.perform(get("/autenticacao/v1/me").principal(auth))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("ana@teste.com"))
                .andExpect(jsonPath("$.username").value("ana"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("hash-secreto"))));
    }
}
