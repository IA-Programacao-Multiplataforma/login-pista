package com.pista.login.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import com.pista.login.domain.entity.User;
import com.pista.login.domain.entity.enumerable.Role;
import com.pista.login.spring.security.dto.AuthUserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

class JwtSecurityTest {

    private static final String SECRET = "segredo-de-teste-com-32-caracteres!";

    private final JwtSecurity jwt = new JwtSecurity(SECRET);

    private static AuthUserDetails usuario(String email, Role... roles) {
        return new AuthUserDetails(new User("id-1", "ana", "hash", email, "01001000", List.of(roles)));
    }

    private static SecretKey chave(String segredo) {
        return Keys.hmacShaKeyFor(segredo.getBytes());
    }

    @Test
    void tokenGuardaOEmailComoSubject() {
        String token = jwt.generateToken(usuario("ana@teste.com", Role.USER));

        assertThat(jwt.getUsername(token)).isEqualTo("ana@teste.com");
    }

    @Test
    void tokenCarregaOsPapeisNaClaimRoles() {
        String token = jwt.generateToken(usuario("admin@teste.com", Role.ADMIN, Role.USER));

        Claims claims = Jwts.parser().verifyWith(chave(SECRET)).build().parseSignedClaims(token).getPayload();

        assertThat(claims.get("roles", List.class)).containsExactly("ROLE_ADMIN", "ROLE_USER");
    }

    @Test
    void tokenValeUmaHora() {
        String token = jwt.generateToken(usuario("ana@teste.com", Role.USER));

        Claims claims = Jwts.parser().verifyWith(chave(SECRET)).build().parseSignedClaims(token).getPayload();
        long duracaoMs = claims.getExpiration().getTime() - claims.getIssuedAt().getTime();

        assertThat(duracaoMs).isEqualTo(60L * 60 * 1000);
        assertThat(jwt.isExpired(token)).isFalse();
    }

    @Test
    void tokenValidoParaODonoMasNaoParaOutroUsuario() {
        String token = jwt.generateToken(usuario("ana@teste.com", Role.USER));

        assertThat(jwt.isTokenValid(token, usuario("ana@teste.com", Role.USER))).isTrue();
        assertThat(jwt.isTokenValid(token, usuario("outra@teste.com", Role.USER))).isFalse();
    }

    @Test
    void tokenAssinadoComOutroSegredoEhRecusado() {
        String falso = Jwts.builder().subject("ana@teste.com")
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(chave("outro-segredo-com-32-caracteres!!")).compact();

        assertThatThrownBy(() -> jwt.getUsername(falso)).isInstanceOf(JwtException.class);
    }

    @Test
    void tokenAdulteradoEhRecusado() {
        String token = jwt.generateToken(usuario("ana@teste.com", Role.USER));

        assertThatThrownBy(() -> jwt.getUsername(token + "x")).isInstanceOf(JwtException.class);
    }

    @Test
    void tokenExpiradoEhRecusado() {
        String vencido = Jwts.builder().subject("ana@teste.com")
                .issuedAt(new Date(System.currentTimeMillis() - 120_000))
                .expiration(new Date(System.currentTimeMillis() - 60_000))
                .signWith(chave(SECRET)).compact();

        assertThatThrownBy(() -> jwt.isExpired(vencido)).isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    void segredoCurtoDemaisNaoSobe() {
        assertThatThrownBy(() -> new JwtSecurity("curto")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new JwtSecurity(null)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void lixoNaoEhTokenValido() {
        assertThatThrownBy(() -> jwt.getUsername("isso-nao-e-um-jwt")).isInstanceOf(JwtException.class);
    }
}
