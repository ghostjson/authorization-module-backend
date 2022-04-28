package com.teezpie.authorization.models;

import lombok.Data;
import lombok.ToString;

/**
 * User object: expected to return this user structure from the auth service
 */
@Data
@ToString
public class User {
    private Long id;
    private String email;
    private String username;
    private boolean emailVerified;
}
