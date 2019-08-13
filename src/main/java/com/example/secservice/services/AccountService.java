package com.example.secservice.services;

import com.example.secservice.entities.AppRole;
import com.example.secservice.entities.AppUser;

public interface AccountService {

    public AppUser saveUser(String username, String password, String confirmedPassword);
    public AppRole saveRole(AppRole roleName);
    public AppUser loadUserByUsername(String username);
    public void addRoleToUser(String username, String roleName);
}
