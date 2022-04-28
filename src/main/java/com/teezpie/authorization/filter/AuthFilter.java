package com.teezpie.authorization.filter;

import com.teezpie.authorization.authentications.TokenAuthentication;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Filter which checks whether the request contains an access token,
 * if access token defined then check, retrieve, and authorize the user
 * if failed return "invalid access token error"
 */
@Slf4j
public class AuthFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    public AuthFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String accessToken = request.getHeader("accessToken");

        request.getSession().removeAttribute("SPRING_SECURITY_CONTEXT");
        try{
            if (accessToken != null){

                TokenAuthentication authRequest = new TokenAuthentication(accessToken);

                Authentication authentication = authenticationManager.authenticate(authRequest);
                SecurityContext securityContext = SecurityContextHolder.getContext();

                securityContext.setAuthentication(authentication);

                HttpSession session = request.getSession(true);
                session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
            }
        }catch (ProviderNotFoundException exception){
            log.warn("Provider not found, exception=" + exception);
            System.out.println("Provider not found");
        }




        filterChain.doFilter(request, response);
    }
}
