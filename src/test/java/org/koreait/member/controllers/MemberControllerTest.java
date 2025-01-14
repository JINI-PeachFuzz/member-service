package org.koreait.member.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

@SpringBootTest
@ActiveProfiles({"default", "test", "jwt"})
@AutoConfigureMockMvc
@Transactional
public class MemberControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper om;

    @Test
    void joinTest() throws Exception {
        // 회원 가입
        RequestJoin form = new RequestJoin();
        form.setEmail("user01@test.org");
        form.setName("사용자01");
        form.setPassword("_aA123456");
        form.setConfirmPassword(form.getPassword());
        form.setRequiredTerms1(true);
        form.setRequiredTerms2(true);
        form.setRequiredTerms3(true);
        form.setOptionalTerms(List.of("advertisement"));

        String body = om.writeValueAsString(form);
        mockMvc.perform(post("/join")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)).andDo(print());

        // 로그인 테스트 - 토큰 발급
        RequestLogin loginForm = new RequestLogin();
        loginForm.setEmail(form.getEmail());
        loginForm.setPassword(form.getPassword());
        String loginBody = om.writeValueAsString(loginForm);
        String body3 = mockMvc.perform(post("/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginBody)).andDo(print()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        // 토큰으로 로그인 처리 테스트
        /*
        Map<String, String> data = om.readValue(body3, new TypeReference<>() {});
        String token = data.get("data");

        mockMvc.perform(get("/test")
                .header("Authorization", "Bearer " + token))
                .andDo(print()); */
    }
}