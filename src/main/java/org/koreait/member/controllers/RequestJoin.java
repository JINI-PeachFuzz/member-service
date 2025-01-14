package org.koreait.member.controllers;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

@Data
public class RequestJoin {

    @Email
    @NotBlank
    private String email; // 이메일

    @NotBlank
    private String name; // 회원명

    @NotBlank
    @Size(min=8)
    private String password; // 비밀번호

    @NotBlank
    private String confirmPassword; // 비밀번호 확인

    @AssertTrue
    private boolean requiredTerms1; // 필수 약관 동의 여부

    @AssertTrue
    private boolean requiredTerms2;

    @AssertTrue
    private boolean requiredTerms3;

    private List<String> optionalTerms; // 선택 약관 동의 여부 - 선택약관은 어떤 약관인지를 구분할 수 있어야 함
}