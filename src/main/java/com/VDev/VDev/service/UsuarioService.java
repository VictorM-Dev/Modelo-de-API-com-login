package com.VDev.VDev.service;

import com.VDev.VDev.error.DuplicateEmailException;
import com.VDev.VDev.error.InvalidCredetialsException;
import com.VDev.VDev.error.UserNotFoundException;
import com.VDev.VDev.model.Usuario;
import com.VDev.VDev.repository.UsuarioRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UsuarioService {
    private UsuarioRepository usuarioRepository;
    private PasswordEncoder passwordEncoder;

    public UsuarioService(UsuarioRepository usuarioRepository, PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void cadastrarUsuario(Usuario usuario) throws RuntimeException {
        if (usuarioRepository.findByEmail(usuario.getEmail()).isPresent()) {
            throw new DuplicateEmailException("Já existe um usuário com esse email!");
        }
        usuarioRepository.save(usuario);
    }

    public Usuario autenticar(String email, String senha) throws RuntimeException {
        Usuario usuarioNoBanco = usuarioRepository.findByEmail(email).orElseThrow(() -> new UserNotFoundException("Usuário não encontrado!"));
        if (passwordEncoder.matches(senha, usuarioNoBanco.getSenha())) {
            usuarioNoBanco.setSenha(null);
            return usuarioNoBanco;
        }
        throw new InvalidCredetialsException("Credênciais incorretas!");
    }
}
