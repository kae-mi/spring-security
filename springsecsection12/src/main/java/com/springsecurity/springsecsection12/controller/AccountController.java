package com.springsecurity.springsecsection12.controller;

import com.springsecurity.springsecsection12.model.Accounts;
import com.springsecurity.springsecsection12.repository.AccountsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class AccountController {

    private final AccountsRepository accountsRepository;

    @GetMapping("/myAccount")
    @PostAuthorize("returnObject.branchAddress == 'SEOUL'")
    // @PostAuthorize("returnObject.branchAddress == '123 Main Street, New York'")
    public Accounts getAccountDetails(@RequestParam long id) {
        Accounts accounts = accountsRepository.findByCustomerId(id);
        if (accounts != null) {
            return accounts;
        } else {
            return null;
        }
    }

    @PostMapping("/preFilterByBranch")
    @PreFilter("filterObject.branchAddress == 'Seoul'")
    public List<Accounts> preFilterAccountsByBranch(@RequestBody List<Accounts> accounts) {
        // 필터링된 계좌 목록만 들어옴
        return accounts.stream()
                .peek(a -> a.setAccountType("Seoul-Only"))
                .collect(Collectors.toList());
    }

    @PostMapping("/postFilterByBranch")
    @PreFilter("filterObject.branchAddress == 'Seoul'")
    public List<Accounts> postFilterAccountsByBranch(@RequestBody List<Accounts> accounts) {

        return accounts.stream()
                .peek(a -> a.setAccountType("Seoul-Only"))
                .collect(Collectors.toList());
    }
}