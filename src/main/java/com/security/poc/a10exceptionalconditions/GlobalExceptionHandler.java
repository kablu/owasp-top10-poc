package com.security.poc.a10exceptionalconditions;

import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Central error handler for the secure A10 endpoints: full detail is logged
 * server-side under a correlation id, while the client only receives a generic
 * message + that id. This is how you avoid stack-trace / internal leakage while
 * still being able to investigate.
 */
@RestControllerAdvice(basePackages = "com.security.poc.a10exceptionalconditions")
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handle(Exception ex) {
        String correlationId = UUID.randomUUID().toString();
        // Details stay on the server only.
        log.error("Unhandled error [correlationId={}]", correlationId, ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                        "error", "An unexpected error occurred.",
                        "correlationId", correlationId));
    }
}
