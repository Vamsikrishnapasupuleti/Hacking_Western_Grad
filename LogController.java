package com.example.log4j.controller;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogController {

	private static Logger log=LogManager.getLogger(LogController.class);
	

    @GetMapping("/")
    public String index(@RequestHeader("X-Api-Version") String name) {
    	log.info("Received a request for API version " + name);
        return "Hello, world!";
    }
}
