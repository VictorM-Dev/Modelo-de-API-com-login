package com.VDev.VDev.error;

import java.io.IOException;

public class DuplicateEmailException extends RuntimeException {
    public DuplicateEmailException(String message){
        super(message);
    }
}
