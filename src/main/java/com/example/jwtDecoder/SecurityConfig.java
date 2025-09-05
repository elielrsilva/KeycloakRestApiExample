package com.example.jwtDecoder;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    interface AuthoritiesConverter extends Converter<Map<String, Object>, Collection<GrantedAuthority>> {}

    @Bean
    public AuthoritiesConverter realmRolesAuthoritiesConverter() {
        return claims -> {
            var realmAccess = (Map<String, Object>) claims.getOrDefault("realm_access", Map.of());
            var roles = (Collection<String>) realmAccess.getOrDefault("roles", List.of());

            return roles.stream()
                    // Adiciona o prefixo "ROLE_" que é uma convenção do Spring
                    .map(roleName -> "ROLE_" + roleName.toUpperCase())
                    // Cria o objeto de permissão que o Spring entende
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        };
    }

    @Bean
    public JwtAuthenticationConverter authenticationConverter(AuthoritiesConverter authoritiesConverter) {

        var jwtAuthenticationConverter = new JwtAuthenticationConverter();

        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Map<String, Object> claims = jwt.getClaims();
            return authoritiesConverter.convert(claims);
        });
        return jwtAuthenticationConverter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationConverter jwtAuthenticationConverter
    ) throws Exception {
        http
                // 1. Habilita a configuração para um Servidor de Recursos OAuth2
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                // 2. Conecta o nosso conversor customizado ao pipeline de segurança
                                .jwtAuthenticationConverter(jwtAuthenticationConverter)
                        )
                );

        http
                // 3. Define as regras de autorização
                .authorizeHttpRequests(authorize -> authorize
                        // Exemplo: a rota /admin só pode ser acessada por quem tem a role ADMIN
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        // Qualquer outra requisição precisa no mínimo de autenticação
                        .anyRequest().authenticated()
                );

        return http.build();
    }

}
