package com.springsecurity.springsecsection7.config;

import com.springsecurity.springsecsection7.exception.CustomAccessDeniedHandler;
import com.springsecurity.springsecsection7.exception.CustomBasicAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("prod")
public class ProjectSecurityProdConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // http.authorizeHttpRequests((requests) -> requests.anyRequest().permitAll());
        // http.authorizeHttpRequests((requests) -> requests.anyRequest().denyAll());
        http.requiresChannel(rcc -> rcc.anyRequest().requiresSecure()) // HTTPS 요청만 받아들임
            .csrf(csrfConfig -> csrfConfig.disable())
            .authorizeHttpRequests((requests) -> requests
                .requestMatchers("/myAccount", "/myBalance", "/myCards", "/myLoans").authenticated()
                .requestMatchers("/notices", "/contact","/error", "/register", "/invalidSession").permitAll());
        http.formLogin(withDefaults());
        
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        // http.exceptionHandling(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));

        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));

        // 세션 만료시 이동할 url 설정
        http.sessionManagement(smc -> smc.invalidSessionUrl("/invalidSession").maximumSessions(1).maxSessionsPreventsLogin(true).expiredUrl("/expiredSession"));

        return http.build();
    }

    /*
    // UserDetailsService 를 이용한 사용자 등록
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }
    */

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // 비밀번호의 강력함을 확인해주는 인터페이스

    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {

        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

}
