package org.koreait.member.controllers;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RequestFindPassword {
    @NotBlank
    private String name; // 회원명

    @NotBlank
    private String mobile; // 휴대전화번호

    @NotBlank
    private String origin; //  프론트 앤드 주소
}