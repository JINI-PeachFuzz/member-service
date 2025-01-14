package org.koreait.member.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.koreait.member.constants.Authority;

@Data
@Entity
@IdClass(AuthoritiesId.class)
@NoArgsConstructor
@AllArgsConstructor
public class Authorities {
    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    private Member member;

    @Id
    @Enumerated(EnumType.STRING)
    @Column(length=15)
    private Authority authority;
}