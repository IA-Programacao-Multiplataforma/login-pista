package com.pista.login.spring.controller;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.pista.login.spring.controller.adapter.UserControllerAdapter;
import com.pista.login.spring.controller.dto.request.UserRequest;
import com.pista.login.spring.controller.dto.response.UserResponse;
import com.pista.login.spring.security.dto.AuthUserDetails;
import com.pista.login.domain.entity.User;
import com.pista.login.domain.entity.enumerable.Role;
import com.pista.login.domain.repository.LoginRepository;

@RestController
@RequestMapping("/usuarios")
public class UserController {

    private final LoginRepository repository;
    private final PasswordEncoder passwordEncoder;

    public UserController(LoginRepository repository, PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
    }

    private User usuarioLogado(Authentication authentication) {
        return ((AuthUserDetails) authentication.getPrincipal()).login();
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    @GetMapping
    public String getLogin() {
        return "Realizar Login";
    }

    // Só a PRÓPRIA conta: o id vem do token, nunca do corpo da requisição
    @PutMapping
    public UserResponse atualizar(@RequestBody UserRequest request, Authentication authentication) {
        User atual = usuarioLogado(authentication);

        String senha = isBlank(request.password())
                ? atual.password()
                : passwordEncoder.encode(request.password());
        String cep = isBlank(request.cep()) ? atual.cep() : request.cep();

        User atualizado = new User(atual.id(), atual.username(), senha, atual.email(), cep, atual.roles());
        return UserControllerAdapter.toResponse(repository.salvar(atualizado));
    }

    @DeleteMapping("/{id}")
    public String deletar(@PathVariable String id, Authentication authentication) {
        User logado = usuarioLogado(authentication);

        if (!logado.id().equals(id) && !logado.roles().contains(Role.ADMIN)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Sem permissão para apagar este usuário");
        }

        repository.deletar(id);
        return "Login deletado do banco";
    }
}
