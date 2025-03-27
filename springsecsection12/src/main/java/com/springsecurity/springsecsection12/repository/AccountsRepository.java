package com.springsecurity.springsecsection12.repository;

import com.springsecurity.springsecsection12.model.Accounts;
import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountsRepository extends CrudRepository<Accounts, Long> {

     /*이 메소드를 호출하는 사용자가 USER 역할을 가지고 있다면 해당 메소드가 호출된다.
     그렇지 않으면, 호출되지 않음.
     @PreAuthorize("hasRole('USER')")*/
    Accounts findByCustomerId(long customerId);

}