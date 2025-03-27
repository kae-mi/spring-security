package com.springsecurity.springsecsection12.config;

import com.springsecurity.springsecsection12.exception.CustomAccessDeniedHandler;
import com.springsecurity.springsecsection12.exception.CustomBasicAuthenticationEntryPoint;
import com.springsecurity.springsecsection12.filter.AuthoritiesLoggingAfterFilter;
import com.springsecurity.springsecsection12.filter.JWTGeneratorFilter;
import com.springsecurity.springsecsection12.filter.JWTValidationFilter;
import com.springsecurity.springsecsection12.filter.RequestValidationBeforeFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("!prod")
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.requiresChannel(rcc -> rcc.anyRequest().requiresInsecure()) // HTTP 요청만 받아들임
            .csrf(csrfConfig -> csrfConfig.disable())

            .sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // cors 관련 설정 -> 프론트 백이 다른 origin 에 있는 환경이라면 굳이 필요하지 않은 설정인가
            .cors(corsConfig -> corsConfig.configurationSource(new CorsConfigurationSource() {
                @Override
                public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                    config.setAllowedMethods(Collections.singletonList("*"));
                    config.setAllowCredentials(true);
                    config.setAllowedHeaders(Collections.singletonList("*"));
                    config.setExposedHeaders(Arrays.asList("Authorization")); // 중요 응답 헤더에 Authorization 이름으로 Jwt 토큰 보낼것임
                    config.setMaxAge(3600L);
                    return config; // 굳이 필요하나?? 포스트맨으로만 테스트할거면 기본적으로 Authorization 헤더에 jwt 토큰 담아서 보낸다는데..
                }
            }))

            //BasicAuthenticationFilter 전에 커스텀 필터인 RequestValidationBeforeFilter 가 수행되도록 설정
            .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)

            // BasicAuthenticationFilter 직후에 커스텀 필터인 AuthoritiesLoggingAfterFilter 가 수행되도록 설정
            .addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)

            // JWTToken 생성 필터와 JWTToken 검증 필터의 위치 설정
            .addFilterAfter(new JWTGeneratorFilter(), BasicAuthenticationFilter.class)
            .addFilterBefore(new JWTValidationFilter(), BasicAuthenticationFilter.class)

            .authorizeHttpRequests((requests) -> requests
                /*.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
                .requestMatchers("/myBalance").hasAnyAuthority("VIEWACCOUNT", "VIEWBALANCE")
                .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                .requestMatchers("/myCards").hasAuthority("VIEWCARDS")*/

                .requestMatchers("/myAccount").authenticated()
                .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/myLoans").hasRole("USER")
                .requestMatchers("/myCards").hasRole("USER")
                .requestMatchers("/user").authenticated()

                .requestMatchers("/notices", "/contact","/error", "/register", "/invalidSession", "/preFilterByBranch", "/postFilterByBranch").permitAll());

        http.formLogin(withDefaults());

        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        // http.exceptionHandling(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));

        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));

        // 세션 만료시 이동할 url 설정
        // 이 설정이 활성화되면 계속 JSESSION 이 만들어짐
        // http.sessionManagement(smc -> smc.invalidSessionUrl("/invalidSession").maximumSessions(3).maxSessionsPreventsLogin(true).expiredUrl("/expiredSession"));

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
