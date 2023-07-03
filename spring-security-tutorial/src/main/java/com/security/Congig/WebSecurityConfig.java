package com.security.Congig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class WebSecurityConfig {

    private static final String[] WHITE_LIST_URLS={
            "/register",
            "/hello",
            "/verifyRegistration*",
            "/resendVerificationToken*",
            "/resetPassword",
            "/savePassword*",
            "/changePassword"
    };

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(11);
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.disable())
                .csrf(csrf-> csrf.disable())
                .authorizeHttpRequests(auth -> auth.requestMatchers(WHITE_LIST_URLS).permitAll());
        return http.build();
    }
}
