package com.example.pw_autorizacion_u4_ab.security;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtils {

    private static final Logger LOG = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${app.jwt.secret}") // inyecta los valores desde el propetties
    private String jwtSecreat = "pass1"; // semilla

    @Value("${app.jwt.expiration.ms}")
    private Integer jwtExpiration = 14400000;

    public String generateJwtToken(String nombre) {

        LOG.info("semilla ------------------:" + jwtSecreat + " " + "tiempo: " + jwtExpiration);

        // este metodo genera el token y las seguridades
        return Jwts.builder().setSubject(nombre).setIssuedAt(new Date()) // fecha actual
                .setExpiration(new Date(System.currentTimeMillis() + this.jwtExpiration)) // tiempo
                .signWith(SignatureAlgorithm.HS512, this.jwtSecreat).compact(); // algoritmo y semilla

    }
}

/*-------------------------
AuthenticationEntryPoint 
------------------------

package com.pweb.pw_api_u3_ab.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger LOG = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            org.springframework.security.core.AuthenticationException authException)
            throws IOException, ServletException {
        LOG.error("UnAutorized error {}", authException.getMessage());
        LOG.error(request.getServletPath());

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

}

----------------------------------------------------------------------------------------
AuthTokenFilter 
-----------------

package com.pweb.pw_api_u3_ab.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    private static final Logger LOG = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Autenticar si el token es valido
        LOG.info(this.parseJwt(request));
        try {
            String jwt = this.parseJwt(request);
            // q no sea nullo el token y sea valido
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                // como es valido el token le voy a autenticar
                String nombre = this.jwtUtils.getUsernameFromJwtToken(jwt);

                // le autenticamos

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(nombre,
                        null,
                        new ArrayList<>());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));// se ejecuta la
                                                                                                      // authtenticacion
                                                                                                      // dentro del
                                                                                                      // filtro
                // seteamos la autenticacion en la session
                SecurityContextHolder.getContext().setAuthentication(authentication);

            }
        } catch (Exception e) {
            // TODO: handle exception

            LOG.error("No se pudo realizar la autenticacion con el token ENVIADO {}", e.getMessage());
        }
        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {

        String valorCompleto = request.getHeader("Authorization");
        if (StringUtils.hasText(valorCompleto) && valorCompleto.startsWith("Bearer ")) { // valida que se aun texto y
                                                                                         // empieze con Bearer
            return valorCompleto.substring(7, valorCompleto.length());
        }
        return null;

    }

}

--------------------------------------------------------------------------------
JwtUtils 
---------------------

package com.pweb.pw_api_u3_ab.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

@Component
public class JwtUtils {

    private static final Logger LOG = LoggerFactory.getLogger(JwtUtils.class);

    @Value("$app.jwt.secret") // inyecta los valores desde el propetties
    private String jwtSecreat; // semilla

    public boolean validateJwtToken(String token) {

        try {
            Jwts.parser().setSigningKey(jwtSecreat).parseClaimsJws(token);

        } catch (ExpiredJwtException e) {
            // TODO: handle exception
            LOG.error(e.getMessage());
        } catch (SignatureException e) {
            LOG.error(e.getMessage());
        }

        return false;
    }

    public String getUsernameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecreat).parseClaimsJws(token).getBody().getSubject();
    }

}


-------------------------
WebSecurity 
----------------------


package com.pweb.pw_api_u3_ab.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class WebSecurity {

    @Autowired
    private AuthEntryPointJwt unAutorizedHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.cors().and().csrf().disable()// desbilitar el cors
                .exceptionHandling().authenticationEntryPoint(unAutorizedHandler)// manego de no autorizados
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests().anyRequest()
                .authenticated();

        http.addFilterBefore(this.AuthenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();

    }

    public AuthTokenFilter AuthenticationJwtTokenFilter() {

        return new AuthTokenFilter();
    }

} */