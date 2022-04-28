package com.teezpie.authorization.configurations;

import com.teezpie.authorization.filter.AuthFilter;
import com.teezpie.authorization.filter.CorsFilter;
import com.teezpie.authorization.providers.TokenAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;

/**
 * Authentication Configuration class
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AuthenticationConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private TokenAuthenticationProvider authenticationProvider;


    @Override
    public void configure(AuthenticationManagerBuilder auth) throws BadCredentialsException{
        auth.authenticationProvider(authenticationProvider);
    }

    @Override
    public void configure(WebSecurity web) throws Exception{
        web.ignoring().antMatchers("*");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        http.addFilterBefore(new CorsFilter(), ChannelProcessingFilter.class);
        http.addFilterBefore(new AuthFilter(getAuthenticationManager()), ChannelProcessingFilter.class);
        http.authorizeRequests().anyRequest().permitAll();
    }

    private AuthenticationManager getAuthenticationManager() throws Exception{
        return super.authenticationManager();
    }


}
