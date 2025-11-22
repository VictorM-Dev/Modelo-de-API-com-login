package com.VDev.VDev.controller;

import com.VDev.VDev.dto.LoginRequest;
import com.VDev.VDev.error.DuplicateEmailException;
import com.VDev.VDev.error.InvalidCredetialsException;
import com.VDev.VDev.error.UserNotFoundException;
import com.VDev.VDev.model.Usuario;
import com.VDev.VDev.service.TokenService;
import com.VDev.VDev.service.UsuarioService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class UsuarioController {
    private UsuarioService usuarioService;
    private PasswordEncoder passwordEncoder;
    private TokenService tokenService;
    public UsuarioController(UsuarioService usuarioService, PasswordEncoder passwordEncoder, TokenService tokenService){
        this.usuarioService = usuarioService;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
    }

    @PostMapping("/cadastrar")
    public ResponseEntity<?> cadastrarUsuario(@RequestBody Usuario usuario){
        try{
            String senhaHash = passwordEncoder.encode(usuario.getSenha());
            usuario.setSenha(senhaHash);
            usuarioService.cadastrarUsuario(usuario);
            return ResponseEntity.ok().build();
        } catch (DuplicateEmailException e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest){
        try{
            String token = tokenService.gerarToken(usuarioService.autenticar(loginRequest.email(), loginRequest.senha()).getUsuarioID());
            return ResponseEntity.ok(token);
        } catch (UserNotFoundException | InvalidCredetialsException e){
            return ResponseEntity.status(401).body(e.getMessage());
        }
    }
}
