package cn.leeshuhao.saml.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

/**
 *
 * @author MrLee
 */
@Service
public class SAMLUserDetailServiceImpl implements SAMLUserDetailsService {
    private static final Logger logger = LoggerFactory.getLogger(SAMLUserDetailServiceImpl.class);

    @Override
    public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        String name = credential.getNameID().getValue();
        return new User(name, "", true, true, true, true, new ArrayList<>());
    }
}
