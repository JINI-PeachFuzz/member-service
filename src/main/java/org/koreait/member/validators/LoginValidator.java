package org.koreait.member.validators;

import lombok.RequiredArgsConstructor;
import org.koreait.member.controllers.RequestLogin;
import org.koreait.member.entities.Member;
import org.koreait.member.repositories.MemberRepository;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Lazy
@Component
@RequiredArgsConstructor
public class LoginValidator implements Validator {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(RequestLogin.class);
    }

    @Override
    public void validate(Object target, Errors errors) {
        if (errors.hasErrors()) {
            return;
        }

        /**
         * 1. 회원이 존재하는지 체크
         * 2. 존재하면 비밀번호가 일치하는지 체크
         */

        RequestLogin form = (RequestLogin) target;
        String email = form.getEmail();
        String password = form.getPassword();
        Member member = memberRepository.findByEmail(email).orElse(null);
        if (member == null) {
            errors.reject("Mismatch.login");
            return;
        }

        //  비밀번호가 일치하지 않는 경우
        if (!passwordEncoder.matches(password, member.getPassword())) {
            errors.reject("Mismatch.login");
        }
    }
}