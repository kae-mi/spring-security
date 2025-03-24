package com.springsecurity.springsecsection9.config;

import com.springsecurity.springsecsection9.exception.CustomAccessDeniedHandler;
import com.springsecurity.springsecsection9.exception.CustomBasicAuthenticationEntryPoint;
import com.springsecurity.springsecsection9.filter.AuthoritiesLoggingAfterFilter;
import com.springsecurity.springsecsection9.filter.RequestValidationBeforeFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

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
            //BasicAuthenticationFilter 전에 커스텀 필터인 RequestValidationBeforeFilter가 수행되도록 설정
            .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)

            // BasicAuthenticationFilter 직후에 커스텀 필터인 AuthoritiesLoggingAfterFilter 가 수행도되록 설정
            .addFilterBefore(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
            .authorizeHttpRequests((requests) -> requests
                /*.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
                .requestMatchers("/myBalance").hasAnyAuthority("VIEWACCOUNT", "VIEWBALANCE")
                .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                .requestMatchers("/myCards").hasAuthority("VIEWCARDS")*/

                .requestMatchers("/myAccount").hasRole("USER")
                .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/myLoans").hasRole("USER")
                .requestMatchers("/myCards").hasRole("USER")
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
