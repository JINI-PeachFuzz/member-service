package org.koreait.member.controllers;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RequestChangePassword {
    @NotBlank
    private String token; // 임시 토큰

    @NotBlank
    private String password; // 변경할 비빌번호
}