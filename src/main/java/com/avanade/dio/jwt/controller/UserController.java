package com.avanade.dio.jwt.controller;

import com.avanade.dio.jwt.data.UserData;
import com.avanade.dio.jwt.service.UserDetailServiceeImpl;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class UserController {


    private final UserDetailServiceeImpl userDetailServicee;

    public UserController(UserDetailServiceeImpl userDetailServicee) {
        this.userDetailServicee = userDetailServicee;
    }

    @GetMapping("/users")
    public List<UserData> listAllUsers(){
        return userDetailServicee.listUsers();
    }
}
