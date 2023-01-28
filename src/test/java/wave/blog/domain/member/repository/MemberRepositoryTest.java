package wave.blog.domain.member.repository;

import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import wave.blog.domain.member.domain.Member;
import wave.blog.domain.member.domain.Role;


import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Transactional
class MemberRepositoryTest {

    @Autowired
    MemberRepository memberRepository;
    @Autowired
    EntityManager em;

    @AfterEach
    public void after(){
        em.clear();
    }

    @Test
    public void 회원저장_성공() throws Exception {
        //given
        Member member = Member.builder().username("username").password("1234567890").name("Member1").nickName("NickName1").role(Role.USER).age(22).build();

        //when
        Member saveMember = memberRepository.save(member);

        //then
        Member findMember = memberRepository.findById(saveMember.getId()).orElseThrow(() -> new RuntimeException("저장된 회원이 없습니다"));//아직 예외 클래스를 만들지 않았기에 RuntimeException으로 처리하겠습니다.

        assertThat(findMember).isSameAs(saveMember);
        assertThat(findMember).isSameAs(member);
    }
    @Test
    public void 오류_회원가입시_이름이_없음() throws Exception {
        //given
        Member member = Member.builder().username("username").password("1234567890").nickName("NickName1").role(Role.USER).age(22).build();


        //when, then
        assertThrows(Exception.class, () -> memberRepository.save(member));
    }

    @Test
    public void 오류_회원가입시_닉네임이_없음() throws Exception {
        //given
        Member member = Member.builder().username("username").password("1234567890").name("Member1").role(Role.USER).age(22).build();

        //when, then
        assertThrows(Exception.class, () -> memberRepository.save(member));
    }

    @Test
    public void 오류_회원가입시_나이가_없음() throws Exception {
        //given
        Member member = Member.builder().username("username").password("1234567890").name("Member1").role(Role.USER).nickName("NickName1").build();

        //when, then
        assertThrows(Exception.class, () -> memberRepository.save(member));
    }

    @Test
    public void 오류_회원가입시_중복된_아이디가_있음() throws Exception {
        //given
        Member member1 = Member.builder().username("username").password("1234567890").name("Member1").role(Role.USER).nickName("NickName1").age(22).build();
        Member member2 = Member.builder().username("username").password("1111111111").name("Member2").role(Role.USER).nickName("NickName2").age(22).build();


        memberRepository.save(member1);
        em.clear();

        //when, then
        assertThrows(Exception.class, () -> memberRepository.save(member2));

    }

    @Test
    public void 성공_회원수정() throws Exception {
        //given
        Member member1 = Member.builder().username("username").password("1234567890").name("Member1").role(Role.USER).nickName("NickName1").age(22).build();
        memberRepository.save(member1);
        em.clear();

        String updatePassword = "updatePassword";
        String updateName = "updateName";
        String updateNickName = "updateNickName";
        int updateAge = 33;

        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

        //when
        Member findMember = memberRepository.findById(member1.getId()).orElseThrow(() -> new Exception());
        findMember.updateAge(updateAge);
        findMember.updateName(updateName);
        findMember.updateNickName(updateNickName);
        findMember.updatePassword(passwordEncoder,updatePassword);
        em.flush();

        //then
        Member findUpdateMember = memberRepository.findById(findMember.getId()).orElseThrow(() -> new Exception());

        assertThat(findUpdateMember).isSameAs(findMember);
        assertThat(passwordEncoder.matches(updatePassword, findUpdateMember.getPassword())).isTrue();
        assertThat(findUpdateMember.getName()).isEqualTo(updateName);
        assertThat(findUpdateMember.getName()).isNotEqualTo(member1.getName());
    }


    @Test
    public void existByUsername_정상작동() throws Exception {
        //given
        String username = "username";
        Member member1 = Member.builder().username(username).password("1234567890").name("Member1").role(Role.USER).nickName("NickName1").age(22).build();
        memberRepository.save(member1);
        em.clear();

        //when, then
        assertThat(memberRepository.existsByUsername(username)).isTrue();
        assertThat(memberRepository.existsByUsername(username+"123")).isFalse();

    }
}