package com.example.pw_autorizacion_u4_ab.repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.example.pw_autorizacion_u4_ab.repository.entidad.Usuario;

@Repository
@Transactional
public class UsuarioRepositoryImpl implements IUsuarioRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public Usuario consultarPorUserName(String userName) {

        var usu = this.entityManager.createQuery("SELECT u FROM Usuario u WHERE u.userName=:datoUserName",
                Usuario.class);
        usu.setParameter("datoUserName", userName);
        return usu.getSingleResult();
    }

}
