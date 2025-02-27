
package org.koreait.member.services;

import lombok.RequiredArgsConstructor;
import org.koreait.global.exceptions.BadRequestException;
import org.koreait.global.libs.Utils;
import org.koreait.global.validators.PasswordValidator;
import org.koreait.member.constants.Authority;
import org.koreait.member.constants.TokenAction;
import org.koreait.member.controllers.RequestChangePassword;
import org.koreait.member.controllers.RequestFindPassword;
import org.koreait.member.controllers.RequestJoin;
import org.koreait.member.entities.Authorities;
import org.koreait.member.entities.Member;
import org.koreait.member.entities.QAuthorities;
import org.koreait.member.entities.TempToken;
import org.koreait.member.exceptions.MemberNotFoundException;
import org.koreait.member.exceptions.TempTokenNotFoundException;
import org.koreait.member.repositories.AuthoritiesRepository;
import org.koreait.member.repositories.MemberRepository;
import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Lazy // 지연로딩 - 최초로 빈을 사용할때 생성
@Service
@RequiredArgsConstructor
@Transactional
public class MemberUpdateService implements PasswordValidator {

    private final MemberRepository memberRepository;
    private final AuthoritiesRepository authoritiesRepository;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;
    private final TempTokenService tempTokenService;
    private final Utils utils;

    /**
     * 커맨드 객체의 타입에 따라서 RequestJoin이면 회원 가입 처리
     *                      RequestProfile이면 회원정보 수정 처리
     * @param form
     */
    public void process(RequestJoin form) {
        // 커맨드 객체 -> 엔티티 객체 데이터 옮기기
        Member member = modelMapper.map(form, Member.class);

        // 선택 약관 -> 약관 항목1||약관 항목2||...
        List<String> optionalTerms = form.getOptionalTerms();
        if (optionalTerms != null) {
            member.setOptionalTerms(String.join("||", optionalTerms));
        }

        // 비밀번호 해시화 - BCrypt
        String hash = passwordEncoder.encode(form.getPassword());
        member.setPassword(hash);
        member.setCredentialChangedAt(LocalDateTime.now());

        // 회원 권한
        Authorities auth = new Authorities();
        auth.setMember(member);
        auth.setAuthority(Authority.USER);  // 회원 권한이 없는 경우 - 회원 가입시, 기본 권한 USER

        save(member, List.of(auth)); // 회원 저장 처리
    }


    /**
     * 회원정보 추가 또는 수정 처리
     *
     */
    private void save(Member member, List<Authorities> authorities) {

        memberRepository.saveAndFlush(member);

        // 회원 권한 업데이트 처리 S

        if (authorities != null) {
            /**
             * 기존 권한을 삭제하고 다시 등록
             */

            QAuthorities qAuthorities = QAuthorities.authorities;
            List<Authorities> items = (List<Authorities>) authoritiesRepository.findAll(qAuthorities.member.eq(member));
            if (items != null) {
                authoritiesRepository.deleteAll(items);
                authoritiesRepository.flush();
            }


            authoritiesRepository.saveAllAndFlush(authorities);
        }

        // 회원 권한 업데이트 처리 E
    }

    /**
     * 회원이 입력한 회원명 + 휴대전화번호로 회원을 찾고
     * 가입한 이메일로 비번 변경 가능한 임시 토큰을 발급하고 메일을 전송
     *
     * @param form
     */
    public void issueToken(RequestFindPassword form) {
        String name = form.getName();
        String mobile = form.getMobile();

        Member member = memberRepository.findByNameAndMobile(name, mobile).orElseThrow(MemberNotFoundException::new);
        String email = member.getEmail();

        TempToken token = tempTokenService.issue(email, TokenAction.PASSWORD_CHANGE, form.getOrigin()); // 토큰 발급
        tempTokenService.sendEmail(token.getToken()); // 이메일 전송

    }

    /**
     * 비밀번호 변경
     *
     * @param form
     */
    public void changePassword(RequestChangePassword form) {
        String token = form.getToken();
        String password = form.getPassword();

        TempToken tempToken = tempTokenService.get(token);
        if (tempToken.getAction() != TokenAction.PASSWORD_CHANGE) {
            throw new TempTokenNotFoundException();
        }

        // 비밀번호 자리수 검증
        if (password.length() < 8) {
            throw new BadRequestException(utils.getMessage("Size.requestJoin.password"));
        }

        // 비밀번호 복잡성 검증
        if (!alphaCheck(password, false) || !numberCheck(password) || !specialCharsCheck(password)) {
            throw new BadRequestException(utils.getMessage("Complexity.requestJoin.password"));
        }

        Member member = tempToken.getMember();

        String hash = passwordEncoder.encode(password);
        member.setPassword(hash);
        member.setCredentialChangedAt(LocalDateTime.now());
        memberRepository.saveAndFlush(member);
    }

}
