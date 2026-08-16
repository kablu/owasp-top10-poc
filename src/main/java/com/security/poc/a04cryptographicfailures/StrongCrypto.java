package com.security.poc.a04cryptographicfailures;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Correct, modern crypto for the A04 "how to do it" demo:
 * AES-256-GCM authenticated encryption with a fresh random IV per message, and
 * BCrypt (slow, salted) for password hashing.
 */
class StrongCrypto {

    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final int IV_BYTES = 12;      // 96-bit nonce recommended for GCM
    private static final int TAG_BITS = 128;

    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();
    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);

    StrongCrypto(String base64Key) {
        byte[] raw = Base64.getDecoder().decode(base64Key);
        // Derive a stable 256-bit key from the configured secret material.
        byte[] key256 = new byte[32];
        System.arraycopy(raw, 0, key256, 0, Math.min(raw.length, 32));
        this.key = new SecretKeySpec(key256, "AES");
    }

    /** Returns Base64(IV || ciphertext || GCM-tag). */
    String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);                        // never reuse an IV with GCM
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            throw new IllegalStateException("encrypt failed", e);
        }
    }

    String decrypt(String base64) {
        try {
            byte[] in = Base64.getDecoder().decode(base64);
            byte[] iv = new byte[IV_BYTES];
            System.arraycopy(in, 0, iv, 0, IV_BYTES);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] pt = cipher.doFinal(in, IV_BYTES, in.length - IV_BYTES);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // GCM tag mismatch => tampered ciphertext; fail closed.
            throw new IllegalStateException("decrypt failed (integrity check)", e);
        }
    }

    String hashPassword(String password) {
        return bcrypt.encode(password);
    }
}
