package com.thami.security.service;

import com.thami.security.auth.*;
import com.thami.security.email.EmailSender;
import com.thami.security.security.EmailValidator;
import com.thami.security.security.token.ConfirmationToken;
import com.thami.security.security.token.ConfirmationTokenService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class RegistrationService {

    private final AuthenticationService authenticationService;
    private final EmailValidator emailValidator;
    private final ConfirmationTokenService confirmTokenService;
    private final EmailSender emailSender;

    public RegistrationService(AuthenticationService authenticationService, EmailValidator emailValidator, ConfirmationTokenService confirmTokenService, EmailSender emailSender) {
        this.authenticationService = authenticationService;
        this.emailValidator = emailValidator;
        this.confirmTokenService = confirmTokenService;
        this.emailSender = emailSender;
    }

    public AuthenticationResponse registerCustomer(IndividualEmailRegisterRequest request, String siteUrl) {
        System.out.println("What is the siteURL: \n\n\n" + siteUrl);
        boolean isValidEmail = emailValidator.test(request.getEmail());
        if (isValidEmail) {
            AuthenticationResponse tokenForNewUser = authenticationService.registerCustomer(request);

            //Since, we are running the spring boot application in localhost, we are hardcoding the
            //url of the server. We are creating a POST request with token param
            String link = siteUrl + "/api/v1/auth/confirm?token=" + tokenForNewUser.getConfirmToken();
            emailSender.sendEmail(request.getEmail(), buildEmail(request.getFirstName(), link));
            return tokenForNewUser;
        } else {
            return AuthenticationResponse.builder()
                    .message(String.format("Email %s, not valid", request.getEmail()))
                    .build();
        }
    }

    public AuthenticationResponse registerCorporate(CorporateEmailRegisterRequest request, String siteUrl) {
        System.out.println("What is the siteURL: \n\n\n" + siteUrl);
        boolean isValidEmail = emailValidator.test(request.getEmail());
        if (isValidEmail) {
            AuthenticationResponse tokenForNewUser = authenticationService.registerCorporate(request);

            //Since, we are running the spring boot application in localhost, we are hardcoding the
            //url of the server. We are creating a POST request with token param
            String link = siteUrl + "/api/v1/auth/confirm?token=" + tokenForNewUser.getConfirmToken();
            emailSender.sendEmail(request.getEmail(), buildEmail(request.getFirstName(), link));
            return tokenForNewUser;
        } else {
            return AuthenticationResponse.builder()
                    .message(String.format("Email %s, not valid", request.getEmail()))
                    .build();
        }
    }

    @Transactional
    public AuthenticationResponse confirmToken(String token) {
        Optional<ConfirmationToken> confirmToken = confirmTokenService.getToken(token);

        if (confirmToken.isEmpty()) {
            return AuthenticationResponse.builder()
                    .confirmToken(token)
                    .message("Token not found!")
                    .build();
//            throw new IllegalStateException();
        }

        if (confirmToken.get().getConfirmedAt() != null) {
            return AuthenticationResponse.builder()
                    .confirmToken(token)
                    .message("Email is already confirmed")
                    .build();
//            throw new IllegalStateException();
        }

        LocalDateTime expiresAt = confirmToken.get().getExpiresAt();

        if (expiresAt.isBefore(LocalDateTime.now())) {
            return AuthenticationResponse.builder()
                    .confirmToken(token)
                    .message("Token is already expired!")
                    .build();
//            throw new IllegalStateException();
        }

        confirmTokenService.setConfirmedAt(token);
        authenticationService.enableUser(confirmToken.get().getUser().getEmail());

        //Returning confirmation message if the token matches
        return AuthenticationResponse.builder()
                .confirmToken(token)
                .message("Your email is confirmed. Thank you for using our service!")
                .build();
    }

    private String buildEmail(String name, String link) {
        return "<div style=\"font-family:Helvetica,Arial,sans-serif;font-size:16px;margin:0;color:#0b0c0c\">\n" +
                "\n" +
                "<span style=\"display:none;font-size:1px;color:#fff;max-height:0\"></span>\n" +
                "\n" +
                "  <table role=\"presentation\" width=\"100%\" style=\"border-collapse:collapse;min-width:100%;width:100%!important\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">\n" +
                "    <tbody><tr>\n" +
                "      <td width=\"100%\" height=\"53\" bgcolor=\"#0b0c0c\">\n" +
                "        \n" +
                "        <table role=\"presentation\" width=\"100%\" style=\"border-collapse:collapse;max-width:580px\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" align=\"center\">\n" +
                "          <tbody><tr>\n" +
                "            <td width=\"70\" bgcolor=\"#0b0c0c\" valign=\"middle\">\n" +
                "                <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse\">\n" +
                "                  <tbody><tr>\n" +
                "                    <td style=\"padding-left:10px\">\n" +
                "                  \n" +
                "                    </td>\n" +
                "                    <td style=\"font-size:28px;line-height:1.315789474;Margin-top:4px;padding-left:10px\">\n" +
                "                      <span style=\"font-family:Helvetica,Arial,sans-serif;font-weight:700;color:#ffffff;text-decoration:none;vertical-align:top;display:inline-block\">Confirm your email</span>\n" +
                "                    </td>\n" +
                "                  </tr>\n" +
                "                </tbody></table>\n" +
                "              </a>\n" +
                "            </td>\n" +
                "          </tr>\n" +
                "        </tbody></table>\n" +
                "        \n" +
                "      </td>\n" +
                "    </tr>\n" +
                "  </tbody></table>\n" +
                "  <table role=\"presentation\" class=\"m_-6186904992287805515content\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse;max-width:580px;width:100%!important\" width=\"100%\">\n" +
                "    <tbody><tr>\n" +
                "      <td width=\"10\" height=\"10\" valign=\"middle\"></td>\n" +
                "      <td>\n" +
                "        \n" +
                "                <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse\">\n" +
                "                  <tbody><tr>\n" +
                "                    <td bgcolor=\"#1D70B8\" width=\"100%\" height=\"10\"></td>\n" +
                "                  </tr>\n" +
                "                </tbody></table>\n" +
                "        \n" +
                "      </td>\n" +
                "      <td width=\"10\" valign=\"middle\" height=\"10\"></td>\n" +
                "    </tr>\n" +
                "  </tbody></table>\n" +
                "\n" +
                "\n" +
                "\n" +
                "  <table role=\"presentation\" class=\"m_-6186904992287805515content\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse;max-width:580px;width:100%!important\" width=\"100%\">\n" +
                "    <tbody><tr>\n" +
                "      <td height=\"30\"><br></td>\n" +
                "    </tr>\n" +
                "    <tr>\n" +
                "      <td width=\"10\" valign=\"middle\"><br></td>\n" +
                "      <td style=\"font-family:Helvetica,Arial,sans-serif;font-size:19px;line-height:1.315789474;max-width:560px\">\n" +
                "        \n" +
                "            <p style=\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\">Hi " + name + ",</p><p style=\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\"> Thank you for registering. Please click on the below link to activate your account: </p><blockquote style=\"Margin:0 0 20px 0;border-left:10px solid #b1b4b6;padding:15px 0 0.1px 15px;font-size:19px;line-height:25px\"><p style=\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\"> <a href=\"" + link + "\">Activate Now</a> </p></blockquote>\n Link will expire in 15 minutes. <p>See you soon</p>" +
                "        \n" +
                "      </td>\n" +
                "      <td width=\"10\" valign=\"middle\"><br></td>\n" +
                "    </tr>\n" +
                "    <tr>\n" +
                "      <td height=\"30\"><br></td>\n" +
                "    </tr>\n" +
                "  </tbody></table><div class=\"yj6qo\"></div><div class=\"adL\">\n" +
                "\n" +
                "</div></div>";
    }
}