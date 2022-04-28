package com.teezpie.authorization.authentications;

import com.teezpie.authorization.models.User;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Token authorization contract
 */
public class TokenAuthentication extends AbstractAuthenticationToken {

    private String token;
    private User user;

    public TokenAuthentication(String token){
        super(null);
        this.token = token;
        setAuthenticated(false);
    }

    public TokenAuthentication(String token, User user, Collection<? extends GrantedAuthority> authorities){
        super(authorities);
        this.token = token;
        this.user = user;
        super.setAuthenticated(true);
    }

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this authentication object.
     */
    public TokenAuthentication(Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
    }

    @Override
    public Object getCredentials() {
        return this.token;
    }

    @Override
    public Object getPrincipal() {
        return this.user;
    }
}
