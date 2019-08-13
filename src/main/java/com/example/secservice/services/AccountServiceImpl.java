package com.example.secservice.services;

import com.example.secservice.dao.AppRoleRepository;
import com.example.secservice.dao.AppUserRepository;
import com.example.secservice.entities.AppRole;
import com.example.secservice.entities.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class AccountServiceImpl  implements  AccountService {

    @Autowired
    private AppUserRepository appUserRepository;
    @Autowired
    private AppRoleRepository appRoleRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

//    public AccountServiceImpl(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
//        this.appUserRepository = appUserRepository;
//        this.appRoleRepository = appRoleRepository;
//        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
//    }

    @Override
    public AppUser saveUser(String username, String password, String confirmedPassword) {

        AppUser user = appUserRepository.findByUsername(username);
        if (user!=null) throw new RuntimeException("User Already exists");
        if (!password.equals(confirmedPassword)) throw new RuntimeException("Please confirm your password");

        AppUser appUser = new AppUser();
        appUser.setUsername(username);
        appUser.setPassword(bCryptPasswordEncoder.encode(password));
        appUser.setActive(true);
        System.out.println(username);

        appUserRepository.save(appUser);
        addRoleToUser(username, "USER");
        return appUser;
    }

    @Override
    public AppRole saveRole(AppRole roleName) {
        return appRoleRepository.save(roleName);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        System.out.println(username+"++++++++++++");
        AppUser appUser = appUserRepository.findByUsername(username);
        System.out.println("User "+appUser);

        AppRole appRole = appRoleRepository.findByRoleName(roleName);
        System.out.println("Role "+appRole);

        appUser.getRoles().add(appRole);
        System.out.println("-------------"+appUser);
    }
}
