package com.VDev.VDev.service;

import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class TokenService {
    private final JwtEncoder jwtEncoder;
    public TokenService(JwtEncoder jwtEncoder){
        this.jwtEncoder=jwtEncoder;
    }

    public String gerarToken(UUID userID){
        var agora = Instant.now();
        var expiraEm = 3000L;
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("VDev")
                .subject(userID.toString())
                .issuedAt(agora)
                .expiresAt(agora.plusSeconds(expiraEm))
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}
