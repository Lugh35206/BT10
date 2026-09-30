package com.example.jwtdemo.dto;

public record LoginResponse(String token, long expiresIn) {}
