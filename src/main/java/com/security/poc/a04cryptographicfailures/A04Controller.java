package com.security.poc.a04cryptographicfailures;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A04:2025 — Cryptographic Failures.
 *
 * <p>Contrasts "encryption theatre" (reversible encoding / broken ciphers with a
 * hardcoded key) against authenticated encryption with a managed key and a
 * per-message random nonce.
 */
@RestController
@RequestMapping("/a04")
public class A04Controller {

    private final WeakCrypto weak = new WeakCrypto();
    private final StrongCrypto strong;

    public A04Controller(@Value("${poc.jwt.strong-secret}") String base64Key) {
        // Reuse the configured 32-byte secret as AES key material for the demo.
        this.strong = new StrongCrypto(base64Key);
    }

    // -----------------------------------------------------------------------
    // VULNERABLE: Base64 is NOT encryption, MD5 is a broken hash, and the key is
    // hardcoded + ECB reveals patterns. Anyone can trivially reverse this.
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/store")
    public Map<String, Object> vulnStore(@RequestParam String data) {
        return Map.of(
            "base64_pretending_to_be_encryption", weak.fakeEncrypt(data),
            "md5_password_hash", weak.md5(data),
            "note", "Base64 is reversible; MD5 is broken. This protects nothing."
        );
    }

    // -----------------------------------------------------------------------
    // SECURE: AES-256-GCM (authenticated encryption) with a random 12-byte IV
    // per message, plus BCrypt for password hashing. Key comes from config
    // (in prod: a KMS/vault), never hardcoded in source.
    // -----------------------------------------------------------------------
    @PostMapping("/secure/store")
    public Map<String, Object> secureStore(@RequestParam String data) {
        String ciphertext = strong.encrypt(data);
        return Map.of(
            "aes_gcm_ciphertext", ciphertext,
            "roundtrip_decrypt", strong.decrypt(ciphertext),
            "bcrypt_password_hash", strong.hashPassword(data),
            "note", "AES-GCM = confidentiality + integrity; random IV; BCrypt is slow+salted."
        );
    }
}
