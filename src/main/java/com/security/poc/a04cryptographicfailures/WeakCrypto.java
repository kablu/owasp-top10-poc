package com.security.poc.a04cryptographicfailures;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Deliberately INSECURE crypto helpers, for the A04 "what not to do" demo.
 * Do not copy any of this into real code.
 */
class WeakCrypto {

    /** Base64 is an encoding, not encryption — fully reversible with no key. */
    String fakeEncrypt(String plaintext) {
        return Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    /** MD5 is cryptographically broken, unsalted, and GPU-crackable. */
    String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return HexFormat.of().formatHex(md.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
