package com.ticketing.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtUtil {

    // ✅ 256-bit+ secure key (DO NOT CHANGE THIS FORMAT)
    private static final SecretKey SECRET_KEY =
            Keys.hmacShaKeyFor(
                    "my-super-secure-jwt-secret-key-which-is-at-least-32-bytes-long"
                            .getBytes()
            );

    private static final long EXPIRATION_TIME = 1000 * 60 * 60; // 1 hour

    // ✅ ONLY GENERATION — NO PARSING YET
    public static String generateToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256) // ✅ CORRECT WAY
                .compact();
    }


    public static Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public static String extractEmail(String token) {
        return extractAllClaims(token).getSubject();
    }

    public static boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }

    public static boolean isTokenValid(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

}
