package com.example.pw_autorizacion_u4_ab.service.dto;

import java.io.Serializable;

import org.springframework.hateoas.RepresentationModel;

public class UsuarioTo extends RepresentationModel implements Serializable {

    private static final long serializableIU = 1L;

    private String userName;

    private String password;

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}
