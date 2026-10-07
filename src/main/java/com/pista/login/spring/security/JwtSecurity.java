package com.pista.login.spring.security;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtSecurity {
    private static final long EXP = 60L * 60 * 1000; // 1 hora (igual ao maxAge do cookie)

    // JWT_SECRET tem que ser o mesmo do gateway, da fila e do pedido, que validam os tokens assinados aqui
    private final byte[] secret;

    public JwtSecurity(@Value("${jwt.secret}") String secret) {
        if (secret == null || secret.getBytes().length < 32) {
            throw new IllegalStateException("jwt.secret (JWT_SECRET) precisa ter pelo menos 32 caracteres");
        }
        this.secret = secret.getBytes();
    }

    private byte[] getSecret() {
        return secret;
    }

    public String generateToken(UserDetails user) {
        Date date = new Date();
        SecretKey key = Keys.hmacShaKeyFor(getSecret());
        return Jwts.builder()
                .subject(user.getUsername())
                .claim("roles", user.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList())
                .issuedAt(date)
                .expiration(new Date(date.getTime() + EXP))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public String getUsername(String token) {
        return parseClaims(token).getSubject();
    }

    public boolean isExpired(String token) {
        return parseClaims(token).getExpiration().before(new Date());
    }

    public boolean isTokenValid(String token, UserDetails user) {
        String username = getUsername(token);
        return username.equals(user.getUsername()) && !isExpired(token);
    }

    private Claims parseClaims(String token) {
        SecretKey secretKey = Keys.hmacShaKeyFor(getSecret());
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}