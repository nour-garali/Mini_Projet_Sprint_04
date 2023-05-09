package com.nour.enseignant.security;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  
    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        PasswordEncoder passwordEncoder = passwordEncoder();
        
        
        auth.userDetailsService(userDetailsService)
        .passwordEncoder(passwordEncoder);

       /* System.out.println("Password Encoded BCRYPT :******************** ");
        System.out.println(passwordEncoder.encode("123"));*/
        

       /* auth.jdbcAuthentication()
                .dataSource(dataSource)
                .usersByUsernameQuery("select username , password , enabled from user where username =?")
                .authoritiesByUsernameQuery(
                        "SELECT u.username, r.role " +
                                "FROM user_role ur, user u , role r " +
                                "WHERE u.user_id = ur.user_id AND ur.role_id = r.role_id AND u.username = ?")
                .passwordEncoder(passwordEncoder)
                .rolePrefix("ROLE_");*/
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/showCreate").hasAnyRole("ADMIN","AGENT")
                .antMatchers("/saveEnseignant").hasAnyRole("ADMIN","AGENT")
                .antMatchers("/listeEnseignants").hasAnyRole("ADMIN","AGENT","USER")
                .antMatchers("/supprimerEnseignant","/modifierEnseignant","/updateEnseignant").hasAnyRole("ADMIN")
                .antMatchers("/webjars/**").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
            .exceptionHandling()
                .accessDeniedPage("/accessDenied");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
