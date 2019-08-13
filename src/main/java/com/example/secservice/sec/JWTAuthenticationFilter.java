package com.example.secservice.sec;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.secservice.entities.AppUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {

        AppUser appUser = new ObjectMapper().readValue(request.getInputStream(),AppUser.class); //recuperer username et password
        return authenticationManager.authenticate(new
                UsernamePasswordAuthenticationToken(appUser.getUsername(),appUser.getPassword()));
        } catch (IOException e) {
            e.printStackTrace();
            throw  new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        User user = (User) authResult.getPrincipal(); // recuperer l'utilisateur actuel
        List<String> roles = new ArrayList<>();
        authResult.getAuthorities().forEach(a -> {  // authorities sont liste des roles
            roles.add(a.getAuthority());
        });

        String jwt = JWT.create()
                .withIssuer(request.getRequestURI())
                .withSubject(user.getUsername())  // nom d'utilisateur
                .withArrayClaim("roles", roles.toArray(new String[roles.size()]))  //role en format String
                .withExpiresAt(new Date(System.currentTimeMillis()+SecurityParams.EXPIRATION)) // date d'expiration
                .sign(Algorithm.HMAC256(SecurityParams.SECRET)); // signer le token avec le secret key

        response.addHeader(SecurityParams.JWT_HEADER_NAME,jwt);  // envoyer le token avec le header


    }

}
