package com.example.secservice.sec;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class JWTAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        response.addHeader("Access-Control-Allow-Origin","*"); //authorizer tout les domains
        response.addHeader("Access-Control-Allow-Headers","Origin,Accept,X-Requested-With,Content-Type,Access-Control-Request-Method," +
                "Access-Control-Request-Headers,authorization"); //quelles sont les entets que je t'authorize
        response.addHeader("Access-Control-Expose-Headers","Access-Control-Allow-Origin,Access-Control-Allow-Credentials,Authorization");
        response.addHeader("Access-Control-Allow-Methods","GET,POST,PUT,DELETE,PATCH");
        if(request.getMethod().equals("OPTION")){  // OPTION demander les options de connexion d'abord qui sont les entetes . c'est la peine de chercher JWT
            response.setStatus(HttpServletResponse.SC_OK);
        }

        else if (request.getRequestURI().equals("/login")){
            filterChain.doFilter(request,response);
            return;
        }

        else {


        String jwt = request.getHeader(SecurityParams.JWT_HEADER_NAME);
        System.out.println("Token "+jwt);
        if(jwt==null || !jwt.startsWith(SecurityParams.HEADER_PREFIX)){
                filterChain.doFilter(request,response);  // rejeter l'acces
            return;
        }

        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SecurityParams.SECRET)).build(); // verifier la signature
        DecodedJWT decodedJWT = verifier.verify(jwt.substring(SecurityParams.HEADER_PREFIX.length())); // verifier le token
        String username = decodedJWT.getSubject(); // recuperer l'username
        List<String> roles = decodedJWT.getClaims().get("roles").asList(String.class); // recuperer la liste des roles
        System.out.println("Username "+username);
        System.out.println("roles "+roles);
        Collection<GrantedAuthority> authorities = new ArrayList<>(); // transformer les roles en une colledtion de GrantedAuthority
        roles.forEach(rn ->{
            authorities.add(new SimpleGrantedAuthority(rn));
        });

        UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(username,null,authorities); // Creation du User de spring
        SecurityContextHolder.getContext().setAuthentication(user);
        filterChain.doFilter(request,response);

        }

    }
}
