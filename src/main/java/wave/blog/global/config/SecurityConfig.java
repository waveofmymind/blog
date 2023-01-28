package wave.blog.global.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import wave.blog.domain.member.application.LoginService;
import wave.blog.domain.member.repository.MemberRepository;
import wave.blog.global.jwt.service.JwtService;
import wave.blog.global.login.filter.JsonUsernamePasswordAuthenticationFilter;
import wave.blog.global.login.filter.JwtAuthenticationProcessingFilter;
import wave.blog.global.login.handler.LoginFailureHandler;
import wave.blog.global.login.handler.LoginSuccessJWTProvideHandler;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final LoginService loginService;
    private final ObjectMapper objectMapper;
    private final MemberRepository memberRepository;
    private final JwtService jwtService;



    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .formLogin().disable()//1 - formLogin 인증방법 비활성화
                .httpBasic().disable()//2 - httpBasic 인증방법 비활성화(특정 리소스에 접근할 때 username과 password 물어봄)
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and().authorizeHttpRequests()
                .requestMatchers("/login", "/signUp","/").permitAll()
                .anyRequest().authenticated();

        http.addFilterAfter(jsonUsernamePasswordLoginFilter(), LogoutFilter.class);
        http.addFilterBefore(jwtAuthenticationProcessingFilter(), JsonUsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() {//2 - AuthenticationManager 등록
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();//DaoAuthenticationProvider 사용
        provider.setPasswordEncoder(passwordEncoder());//PasswordEncoder로는 PasswordEncoderFactories.createDelegatingPasswordEncoder() 사용
        provider.setUserDetailsService(loginService); //이후 작성할 코드입니다.
        return new ProviderManager(provider);
    }

    @Bean
    public LoginSuccessJWTProvideHandler loginSuccessJWTProvideHandler(){
        return new LoginSuccessJWTProvideHandler(jwtService, memberRepository);//변경
    }

    @Bean
    public LoginFailureHandler loginFailureHandler(){
        return new LoginFailureHandler();
    }

    @Bean
    public JsonUsernamePasswordAuthenticationFilter jsonUsernamePasswordLoginFilter(){
        JsonUsernamePasswordAuthenticationFilter jsonUsernamePasswordLoginFilter = new JsonUsernamePasswordAuthenticationFilter(objectMapper);
        jsonUsernamePasswordLoginFilter.setAuthenticationManager(authenticationManager());
        jsonUsernamePasswordLoginFilter.setAuthenticationSuccessHandler(loginSuccessJWTProvideHandler());
        jsonUsernamePasswordLoginFilter.setAuthenticationFailureHandler(loginFailureHandler());
        return jsonUsernamePasswordLoginFilter;
    }

    @Bean
    public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter(){
        JwtAuthenticationProcessingFilter jsonUsernamePasswordLoginFilter = new JwtAuthenticationProcessingFilter(jwtService, memberRepository);

        return jsonUsernamePasswordLoginFilter;
    }
}

