package com.teezpie.authorization.providers;

import com.teezpie.authorization.authentications.TokenAuthentication;
import com.teezpie.authorization.models.User;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;


/**
 * Token Authentication Provider
 */
@Slf4j
@Component
public class TokenAuthenticationProvider implements AuthenticationProvider {


    @Value("${app.auth.base_url}")
    private String authBaseURL;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        RestTemplate restTemplate = new RestTemplate();

        log.debug("HIT: authenticate(), authentication=" + authentication);


        try{
            String accessToken = authentication.getCredentials().toString();

            // send request to the auth service to check and retrieve user details
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "Basic " + new String(Base64.encodeBase64("client:secret".getBytes())));
            headers.add("Content-Type", "application/json");

            HttpEntity<String> httpEntity = new HttpEntity<>("{\"accessToken\": \""+ accessToken +"\"}", headers);
            ResponseEntity<User> result = restTemplate.exchange(authBaseURL + "/api/v1/auth/user", HttpMethod.POST, httpEntity, User.class);

            log.debug("User data with token=" + accessToken + ", user=" + result.getBody());

            return new TokenAuthentication(accessToken, result.getBody(), Collections.emptyList());
        }catch (HttpClientErrorException | NullPointerException e){
            return null;
        }


    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(TokenAuthentication.class);
    }
}
