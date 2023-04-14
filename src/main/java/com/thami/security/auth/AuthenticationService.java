package com.thami.security.auth;

import com.thami.security.security.config.JwtService;
import com.thami.security.security.token.ConfirmationToken;
import com.thami.security.security.token.ConfirmationTokenService;
import com.thami.security.security.token.JwtToken;
import com.thami.security.security.token.TokenType;
import com.thami.security.repository.TokenRepository;
import com.thami.security.repository.UserRepository;
import com.thami.security.model.Role;
import com.thami.security.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final ConfirmationTokenService confirmationTokenService;

    public AuthenticationResponse register(RegisterRequest request) {
        boolean userExists = userRepository.findByEmail(request.getEmail()).isPresent();
        String token = null;
        if (userExists) {

            User appUserPrevious =  userRepository.findByEmail(request.getEmail()).get();
            Boolean isEnabled = appUserPrevious.getEnabled();

            if (!isEnabled) {
                token = UUID.randomUUID().toString();

                //A method to save user and token in this class
                saveConfirmationToken(appUserPrevious, token);

                return AuthenticationResponse.builder()
                        .confirmToken(token)
                        .build();

            }
            throw new IllegalStateException(String.format("User with email %s already exists!", request.getEmail()));
        }

        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .enabled(false)
                .locked(false)
                .build();

        var savedUser = userRepository.save(user);
//        var jwtToken = jwtService.generateJwtToken(user);

//        saveUserToken(savedUser, jwtToken);
        token = UUID.randomUUID().toString();

        saveConfirmationToken(savedUser, token);

        return AuthenticationResponse.builder()
                .jwtToken("")
                .confirmToken(token)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();

        var jwtToken = jwtService.generateJwtToken(user);

        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);

        return AuthenticationResponse.builder()
                .jwtToken(jwtToken)
                .build();
    }

    private void saveConfirmationToken(User user, String token) {
        ConfirmationToken confirmationToken = new ConfirmationToken(token, LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15), user);
        confirmationTokenService.saveConfirmationToken(confirmationToken);
    }

    public int enableUser(String email) {
        return userRepository.enableUser(email);
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = JwtToken.builder()
                .user(user)
                .jwtToken(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidJwtTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(jwtToken -> {
            jwtToken.setExpired(true);
            jwtToken.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
}
