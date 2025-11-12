package com.custard.gatewayserver.infrastructure;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity serverHttpSecurity
    ) {
        serverHttpSecurity.authorizeExchange(exchanges ->
                exchanges
                        .pathMatchers("/accounts/api/v1/create").permitAll()
                        .pathMatchers("/accounts/api/v1/login").permitAll()
                        .pathMatchers("/accounts/api/v1/ping").permitAll()
                        .pathMatchers("/accounts/api/v1/refreshToken").permitAll()
                        // internal
                        .pathMatchers(
                                "/ping",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/webjars/**",
                                "/swagger-ui.html",
                                "/actuator/**")
                        .permitAll()
                        // accounts service opened swagger
                        .pathMatchers(
                                "/v3/api-docs/swagger-config",
                                "/accounts/swagger-ui.html",
                                "/accounts/swagger-ui/**",
                                "/accounts/v3/api-docs/**",
                                "/accounts/webjars/**",
                                "/accounts/swagger-resources/**").permitAll()

                        // communication service opened swagger endpoints
                        .pathMatchers("/communications/swagger-ui/**",
                                "/communications/v3/api-docs/**",
                                "/communications/v3/api-docs/**",
                                "/communications/webjars/**",
                                "/communications/swagger-resources/**"
                        ).permitAll()

                        .pathMatchers("/accounts/**").authenticated()
                        .pathMatchers("/communications/**").authenticated()

        ).oauth2ResourceServer(oAuth2ResourceServerSpec ->
                oAuth2ResourceServerSpec.jwt(jwtSpec ->
                        jwtSpec.jwtAuthenticationConverter(grantedAuthoritiesExtractor())));
        serverHttpSecurity.csrf(ServerHttpSecurity.CsrfSpec::disable);
        return serverHttpSecurity.build();
    }

    private Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
        JwtAuthenticationConverter jwtAuthenticationConverter =
                new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
                new KeycloakRoleConverter()
        );
        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }

}
