package com.estc.mediatech_2.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.Map;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, String>> handleRuntimeException(RuntimeException ex) {
        log.warn("Business rule failure: {}", ex.getMessage());
        return ResponseEntity.badRequest()
                .body(Map.of("message", "The request could not be processed"));
    }
}
////////////////////////////ALMOST ENTIRE FILE ALTERED////////////////////////////