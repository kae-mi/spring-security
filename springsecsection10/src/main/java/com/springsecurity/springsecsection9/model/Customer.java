package com.springsecurity.springsecsection9.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Entity
@Table(name = "customer")
@Getter @Setter
public class Customer {

    @Id
    // DB 서버에서 자동으로 시퀀스값을 증가시키도록 설정했기에 스프링은 시퀀스값을 생성하지 않도록 하는 설정을 사용한다.
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    private String email;

    private String pwd;

    private String role;

    @OneToMany(mappedBy = "customer", fetch = FetchType.EAGER)
    private Set<Authority> authorities;
}