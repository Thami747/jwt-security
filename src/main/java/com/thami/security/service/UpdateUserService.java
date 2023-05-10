package com.thami.security.service;

import com.thami.security.model.Auth;
import com.thami.security.model.Corporate;
import com.thami.security.model.Individual;
import com.thami.security.model.Role;
import com.thami.security.model.request.UpdateUserRequest;
import com.thami.security.model.response.UpdateUserResponse;
import com.thami.security.repository.AuthorizationRepository;
import com.thami.security.repository.CorporateRepository;
import com.thami.security.repository.IndividualRepository;
import com.thami.security.security.EmailValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UpdateUserService {
    private final EmailValidator emailValidator;
    private final AuthorizationRepository authorizationRepository;
    private final IndividualRepository individualRepository;
    private final CorporateRepository corporateRepository;

    public UpdateUserResponse updateUser(UpdateUserRequest updateUserRequest, String username) {
        Optional<Auth> appUser = authorizationRepository.findByEmail(username);

        if (appUser.isPresent() && appUser.get().getRole() == Role.INDIVIDUAL) {
            Individual individual = individualRepository.findByEmail(username).orElseThrow();
//            var user = Individual
//                    .builder()
//                    .firstName(updateUserRequest.getFirstName())
//                    .lastName(updateUserRequest.getLastName())
//                    .cellNumber(updateUserRequest.getCellNumber())
//                    .build();
            individual.setFirstName(updateUserRequest.getFirstName());
            individual.setLastName(updateUserRequest.getLastName());
            individual.setCellNumber(updateUserRequest.getCellNumber());

            individualRepository.save(individual);

            return UpdateUserResponse.builder()
                    .individual(individual)
                    .message("Individual successfully updated!")
                    .build();
        } else if (appUser.isPresent() && appUser.get().getRole() == Role.CORPORATE){
            Corporate corporate = corporateRepository.findByEmail(username).orElseThrow();
//            var user = Corporate
//                    .builder()
//                    .firstName(updateUserRequest.getFirstName())
//                    .lastName(updateUserRequest.getLastName())
//                    .cellNumber(updateUserRequest.getCellNumber())
//                    .build();
            corporate.setCellNumber(updateUserRequest.getCompanyName());
            corporate.setCompanyRegistrationNumber(updateUserRequest.getCompanyRegistrationNumber());
            corporate.setCellNumber(updateUserRequest.getCellNumber());
            corporate.setNumberOfEmployees(updateUserRequest.getNumberOfEmployees());

            corporateRepository.save(corporate);

            return UpdateUserResponse.builder()
                    .corporate(corporate)
                    .message("Corporate successfully updated!")
                    .build();
        } else {
            return UpdateUserResponse.builder()
                    .message("USER does not exist!!!")
                    .build();
        }
    }
}
