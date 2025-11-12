package com.custard.gatewayserver.rest;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/")
public class AppController {
    @GetMapping("/ping")
    public ResponseEntity<String> ping(){
        return ResponseEntity.ok("ping");
    }
}
