package com.pista.login.spring.security;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthFilterSecurity extends OncePerRequestFilter {
    
    private final JwtSecurity jwt;
    private final UserDetailsService service;
    
    private static final String ACCESS_TOKEN_COOKIE = "access_token"; 

    public JwtAuthFilterSecurity(JwtSecurity jwt, UserDetailsService service) {
        this.jwt = jwt;
        this.service = service;
    }

    private String extrairUsername(String token) {
        try {
            return jwt.getUsername(token);
        } catch (JwtException | IllegalArgumentException e) {
            return null;
        }
    }

    private UserDetails carregarUsuario(String username) {
        try {
            return service.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            return null;
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getServletPath();
        return path.equals("/autenticacao/v1/login") || path.equals("/autenticacao/v1/create");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String token = null;

        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (ACCESS_TOKEN_COOKIE.equals(cookie.getName())) {
                    token = cookie.getValue();
                    break;
                }
            }
        }

        if (token == null) {
            String header = request.getHeader("Authorization");
            if (header != null && header.startsWith("Bearer ")) {
                token = header.substring(7);
            }
        }
        
        if (token != null) {
            String username = extrairUsername(token);            
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                
                UserDetails userDetails = carregarUsuario(username);
                
                if (userDetails != null && jwt.isTokenValid(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, 
                            null, 
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
}