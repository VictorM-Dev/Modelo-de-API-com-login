package com.VDev.VDev.model;

import jakarta.persistence.*;

import java.util.UUID;

@Entity
@Table(name = "usuarios")
public class Usuario {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID usuarioID;

    @Column(unique = true)
    private String email;
    private String senha;

    public Usuario(){}
    public Usuario(UUID usuarioID, String email, String senha) {
        this.usuarioID = usuarioID;
        this.email = email;
        this.senha = senha;
    }

    public UUID getUsuarioID() {
        return usuarioID;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getSenha() {
        return senha;
    }

    public void setSenha(String senha) {
        this.senha = senha;
    }
}
