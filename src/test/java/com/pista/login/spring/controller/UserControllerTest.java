package com.pista.login.spring.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.pista.login.domain.entity.User;
import com.pista.login.domain.entity.enumerable.Role;
import com.pista.login.domain.repository.LoginRepository;
import com.pista.login.spring.security.dto.AuthUserDetails;

class UserControllerTest {

    private final LoginRepository repository = mock(LoginRepository.class);
    private final PasswordEncoder encoder = new BCryptPasswordEncoder();

    private final User ana = new User("ana-id", "ana", encoder.encode("senha-antiga"), "ana@teste.com", "01001000", List.of(Role.USER));
    private final User admin = new User("admin-id", "admin", "hash", "admin@teste.com", "01001000", List.of(Role.ADMIN, Role.USER));

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.standaloneSetup(new UserController(repository, encoder)).build();
        when(repository.salvar(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    private static UsernamePasswordAuthenticationToken logado(User user) {
        return new UsernamePasswordAuthenticationToken(new AuthUserDetails(user), null);
    }

    @Test
    void atualizaCepESenhaDaPropriaConta() throws Exception {
        mvc.perform(put("/usuarios").principal(logado(ana)).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"cep\":\"99999999\",\"password\":\"senha-nova\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cep").value("99999999"));

        ArgumentCaptor<User> salvo = ArgumentCaptor.forClass(User.class);
        verify(repository).salvar(salvo.capture());
        assertThat(salvo.getValue().cep()).isEqualTo("99999999");
        assertThat(encoder.matches("senha-nova", salvo.getValue().password())).isTrue();
    }

    @Test
    void camposEmBrancoMantemOsValoresAtuais() throws Exception {
        mvc.perform(put("/usuarios").principal(logado(ana)).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isOk());

        ArgumentCaptor<User> salvo = ArgumentCaptor.forClass(User.class);
        verify(repository).salvar(salvo.capture());
        assertThat(salvo.getValue().password()).isEqualTo(ana.password());
        assertThat(salvo.getValue().cep()).isEqualTo("01001000");
    }

    @Test
    void naoDaParaTrocarIdEmailUsernameNemPapeisPeloCorpo() throws Exception {
        String ataque = """
                {"id":"admin-id","email":"outro@teste.com","username":"outro","roles":["ADMIN"],"cep":"99999999"}
                """;

        mvc.perform(put("/usuarios").principal(logado(ana)).contentType(MediaType.APPLICATION_JSON).content(ataque))
                .andExpect(status().isOk());

        ArgumentCaptor<User> salvo = ArgumentCaptor.forClass(User.class);
        verify(repository).salvar(salvo.capture());
        assertThat(salvo.getValue().id()).isEqualTo("ana-id");
        assertThat(salvo.getValue().email()).isEqualTo("ana@teste.com");
        assertThat(salvo.getValue().username()).isEqualTo("ana");
        assertThat(salvo.getValue().roles()).containsExactly(Role.USER);
    }

    @Test
    void usuarioApagaAPropriaConta() throws Exception {
        mvc.perform(delete("/usuarios/ana-id").principal(logado(ana)))
                .andExpect(status().isOk());

        verify(repository).deletar("ana-id");
    }

    @Test
    void usuarioNaoApagaContaDeOutro() throws Exception {
        mvc.perform(delete("/usuarios/admin-id").principal(logado(ana)))
                .andExpect(status().isForbidden());

        verify(repository, never()).deletar(any());
    }

    @Test
    void adminApagaQualquerConta() throws Exception {
        mvc.perform(delete("/usuarios/ana-id").principal(logado(admin)))
                .andExpect(status().isOk());

        verify(repository).deletar("ana-id");
    }
}
