package com.example.pw_autorizacion_u4_ab.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.pw_autorizacion_u4_ab.security.JwtUtils;
import com.example.pw_autorizacion_u4_ab.service.UsuarioServiceImpl;
import com.example.pw_autorizacion_u4_ab.service.dto.UsuarioTo;

@RequestMapping("/tokens")
@RestController
@CrossOrigin
public class TokenControllerResful {

    @Autowired
    private UsuarioServiceImpl usuarioService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @GetMapping("/obtener")
    public String obtenerToken(@RequestBody UsuarioTo usuario) {

        this.authenticated(usuario.getUserName(), usuario.getPassword()); // Spring valida las credenciales

        return jwtUtils.generateJwtToken(usuario.getUserName());

    }

    private void authenticated(String usuario, String password) { // metodo para authenticar

        Authentication authentication = this.authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(usuario, password));

        SecurityContextHolder.getContext().setAuthentication(authentication);

    }

}
