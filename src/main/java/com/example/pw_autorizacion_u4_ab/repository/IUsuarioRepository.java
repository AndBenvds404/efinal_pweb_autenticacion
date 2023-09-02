package com.example.pw_autorizacion_u4_ab.repository;

import com.example.pw_autorizacion_u4_ab.repository.entidad.Usuario;

public interface IUsuarioRepository {

    public Usuario consultarPorUserName(String userName);
}
