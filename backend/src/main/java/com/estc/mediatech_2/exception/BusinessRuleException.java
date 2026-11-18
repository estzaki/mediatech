package com.estc.mediatech_2.exception;

/** Error whose message was written for the end user and is safe to show. */
public class BusinessRuleException extends RuntimeException {
    public BusinessRuleException(String message) {
        super(message);
    }
}


///////////////////////ADDED FILE////////////////////////////