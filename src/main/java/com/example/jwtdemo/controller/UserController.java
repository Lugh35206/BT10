package com.example.jwtdemo.controller;

import com.example.jwtdemo.dto.UserResponse;
import com.example.jwtdemo.entity.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {

    @GetMapping("/me")
    public ResponseEntity<UserResponse> me(@AuthenticationPrincipal User currentUser) {
        return ResponseEntity.ok(
                new UserResponse(currentUser.getId(), currentUser.getEmail(), currentUser.getFullName()));
    }
}
