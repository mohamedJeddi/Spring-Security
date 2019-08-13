package com.example.secservice;

import com.example.secservice.entities.AppRole;
import com.example.secservice.entities.AppUser;
import com.example.secservice.services.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.stream.Stream;

@SpringBootApplication
public class SecServiceApplication implements CommandLineRunner {

    @Autowired
    public AccountService accountService;

    public static void main(String[] args) {
        SpringApplication.run(SecServiceApplication.class, args);
    }


    @Bean
    BCryptPasswordEncoder getBCPE() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void run(String... args) throws Exception {

          accountService.saveRole(new AppRole("USER"));
          accountService.saveRole(new AppRole("ADMIN"));

            Stream.of("user1","user2","user3","admin").forEach(un -> {
                accountService.saveUser(un,"1234","1234");
            });

            accountService.addRoleToUser("admin","ADMIN");
    };

}
