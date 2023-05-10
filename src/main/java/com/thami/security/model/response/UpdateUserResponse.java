package com.thami.security.model.response;

import com.thami.security.model.Corporate;
import com.thami.security.model.Individual;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateUserResponse {
    private Corporate corporate;
    private Individual individual;
    private String message;
}
