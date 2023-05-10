package com.thami.security.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thami.security.model.*;
import com.thami.security.repository.*;
import com.thami.security.security.config.JwtService;
import com.thami.security.security.token.ConfirmationToken;
import com.thami.security.security.token.ConfirmationTokenService;
import com.thami.security.security.token.JwtToken;
import com.thami.security.security.token.TokenType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final AuthorizationRepository authorizationRepository;
    private final IndividualRepository individualRepository;
    private final CorporateRepository corporateRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final ConfirmationTokenService confirmationTokenService;

    public AuthenticationResponse registerCustomer(IndividualEmailRegisterRequest request) {
        boolean userExists = authorizationRepository.findByEmail(request.getEmail()).isPresent();
        String token = null;
        if (userExists) {

            Auth auth =  authorizationRepository.findByEmail(request.getEmail()).get();
            Boolean isEnabled = auth.getEnabled();

            if (!isEnabled) {
                token = UUID.randomUUID().toString();

                //A method to save individual and token in this class
                saveUserConfirmationToken(auth, token);

                return AuthenticationResponse.builder()
                        .confirmToken(token)
                        .build();

            }else {
                return AuthenticationResponse.builder()
                        .message(String.format("Individual with email %s already exists!", request.getEmail()))
                        .build();
            }
        }

        //Save user to the Individual table ---------------------------------------------------
        var individual = Individual.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        var savedIndividualProfile = individualRepository.save(individual);

        var user = Auth.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .username(request.getEmail())
                .role(request.getRole())
                .enabled(false)
                .locked(false)
                .credentialsNonExpired(false)
                .accountNonExpired(false)
                .individual(savedIndividualProfile)
                .build();

        var savedIndividualUser = authorizationRepository.save(user);
        token = UUID.randomUUID().toString();

        saveUserConfirmationToken(savedIndividualUser, token);

        var jwtToken = jwtService.generateToken(savedIndividualUser);

        saveUserJwtToken(savedIndividualUser, jwtToken);

        return AuthenticationResponse.builder()
                .jwtToken(jwtToken)
                .confirmToken(token)
                .message("Successfully registered new individual!")
                .build();
    }

    public AuthenticationResponse registerCorporate(CorporateEmailRegisterRequest request) {
        boolean userExists = authorizationRepository.findByEmail(request.getEmail()).isPresent();
        String token = null;
        if (userExists) {

            Auth auth =  authorizationRepository.findByEmail(request.getEmail()).get();
            Boolean isEnabled = auth.getEnabled();

            if (!isEnabled) {
                token = UUID.randomUUID().toString();

                //A method to save company and token in this class
                saveUserConfirmationToken(auth, token);

                return AuthenticationResponse.builder()
                        .confirmToken(token)
                        .message("Successfully registered new corporate!")
                        .build();

            } else {
                return AuthenticationResponse.builder()
                        .message(String.format("Company with email %s already exists!", request.getEmail()))
                        .build();
            }
        }

        //Save user to the Corporate table ---------------------------------------------------
        var corporate = Corporate.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        var savedCorporateProfile = corporateRepository.save(corporate);

        var user = Auth.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .username(request.getEmail())
                .role(request.getRole())
                .enabled(false)
                .locked(false)
                .credentialsNonExpired(false)
                .accountNonExpired(false)
                .corporate(savedCorporateProfile)
                .build();

        var savedCorporateUser = authorizationRepository.save(user);
        token = UUID.randomUUID().toString();

        saveUserConfirmationToken(savedCorporateUser, token);

        var jwtToken = jwtService.generateToken(savedCorporateUser);

        saveUserJwtToken(savedCorporateUser, jwtToken);

        return AuthenticationResponse.builder()
                .jwtToken(jwtToken)
                .confirmToken(token)
                .message("Successfully registered new corporate!")
                .build();
    }

    public LoginResponse authenticate(AuthenticationRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            var user = authorizationRepository.findByEmail(request.getEmail())
                    .orElseThrow();

            var jwtToken = jwtService.generateToken(user);

            revokeAllUserTokens(user);
            saveUserJwtToken(user, jwtToken);

            return LoginResponse.builder()
                    .jwtToken(jwtToken)
                    .role(user.getRole())
                    .message("Successfully logged in!")
                    .build();

        } catch (AuthenticationException e) {
            return LoginResponse.builder()
                    .message(e.getMessage())
                    .build();
        }
    }

    private void saveUserConfirmationToken(Auth auth, String token) {
        ConfirmationToken confirmationToken = new ConfirmationToken(token, LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15), auth);
        confirmationTokenService.saveConfirmationToken(confirmationToken);
    }

    public int enableUser(String email) {
        return authorizationRepository.enableUser(email);
    }

    private void saveUserJwtToken(Auth user, String jwtToken) {
        var token = JwtToken.builder()
                .auth(user)
                .jwtToken(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(Auth auth) {
        var validUserTokens = tokenRepository.findAllValidJwtTokensByUser(auth.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(jwtToken -> {
            jwtToken.setExpired(true);
            jwtToken.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.authorizationRepository.findByEmail(userEmail)
                    .orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserJwtToken(user, accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .jwtToken(accessToken)
                        .refreshToken(refreshToken)
                        .message("Successfully refreshed JWT Token!!!")
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}
