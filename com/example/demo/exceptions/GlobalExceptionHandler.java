package com.example.demo.exceptions;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.View;

import java.nio.file.AccessDeniedException;
import java.security.SignatureException;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private final View error;

    public GlobalExceptionHandler(View error) {
        this.error = error;
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleSecurityException(Exception exception) {
        ProblemDetail errorDetails = null;
        if (exception instanceof BadCredentialsException) {
            errorDetails = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401), exception.getMessage());
            errorDetails.setProperty("description", "The username or password in incorrect");
            return errorDetails;
        }
        if(exception instanceof AccessDeniedException) {
            errorDetails = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), exception.getMessage());
            errorDetails.setProperty("description", "You are not authorized to access this resource");
        }

        if(exception instanceof SignatureException) {
            errorDetails = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), exception.getMessage());
            errorDetails.setProperty("description", "The JWT signature is invalid");
        }
        if(exception instanceof ExpiredJwtException) {
            errorDetails = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), exception.getMessage());
            errorDetails.setProperty("description", "The JWT token has expired");
        }
        if(exception instanceof AccountStatusException) {
            errorDetails = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), exception.getMessage());
            errorDetails.setProperty("description", "The Accound is Locked");
        }
        if(errorDetails == null) {
            errorDetails = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(500), exception.getMessage());
            errorDetails.setProperty("description", "Unknown internal server error");
        }
        return errorDetails;

    }

}
