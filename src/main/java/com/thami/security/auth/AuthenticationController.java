package com.thami.security.auth;

import com.thami.security.service.RegistrationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final RegistrationService registrationService;

    @PostMapping("/individual/register")
    public ResponseEntity<AuthenticationResponse> registerCustomer(@RequestBody IndividualEmailRegisterRequest userRequest, HttpServletRequest httpServletRequest) {
        return ResponseEntity.ok(registrationService.registerCustomer(userRequest, getSiteURL(httpServletRequest)));
    }

    @PostMapping("/corporate/register")
    public ResponseEntity<AuthenticationResponse> registerCorporate(@RequestBody CorporateEmailRegisterRequest userRequest, HttpServletRequest httpServletRequest) {
        return ResponseEntity.ok(registrationService.registerCorporate(userRequest, getSiteURL(httpServletRequest)));
    }

    @GetMapping(path = "confirm")
    public ResponseEntity<AuthenticationResponse> confirm(@RequestParam("token") String token) {
        return ResponseEntity.ok(registrationService.confirmToken(token));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<LoginResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        authenticationService.refreshToken(request, response);
    }

    private String getSiteURL(HttpServletRequest request) {
        String siteURL = request.getRequestURL().toString();
        return siteURL.replace(request.getServletPath(), "");
    }
}
