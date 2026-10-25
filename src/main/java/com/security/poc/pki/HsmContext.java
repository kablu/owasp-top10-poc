package com.security.poc.pki;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

/**
 * Opens a connection to SoftHSM (or any PKCS#11 token) through the JDK's
 * {@code SunPKCS11} provider and exposes the token as a {@link KeyStore}.
 *
 * <p>How it binds to SoftHSM:
 * <ol>
 *   <li>{@code SunPKCS11} is configured from a small .cfg file that names the
 *       native PKCS#11 library ({@code libsofthsm2.so}) and the slot.</li>
 *   <li>The provider is registered, then a {@code KeyStore} of type
 *       {@code PKCS11} is loaded with the token's <b>user PIN</b>.</li>
 *   <li>Every private-key operation afterwards (key generation, signing) is
 *       performed <b>inside the HSM</b> — the private key never leaves the token.</li>
 * </ol>
 *
 * <p><b>Must run on the same OS as the native library.</b> SoftHSM here lives in
 * WSL (Linux), so the JVM must run in WSL too — a Windows JVM cannot load a Linux
 * {@code .so}.
 */
public final class HsmContext implements AutoCloseable {

    private final Provider provider;
    private final KeyStore keyStore;

    /**
     * @param pkcs11ConfigPath absolute path to the SunPKCS11 .cfg file
     * @param userPin          the token user PIN (SoftHSM demo token: 1234)
     */
    public HsmContext(String pkcs11ConfigPath, char[] userPin) throws Exception {
        Provider base = Security.getProvider("SunPKCS11");
        if (base == null) {
            throw new IllegalStateException(
                    "SunPKCS11 provider not available in this JDK (need module jdk.crypto.cryptoki)");
        }
        // Java 9+: configure() returns a new, named provider instance bound to the cfg.
        this.provider = base.configure(pkcs11ConfigPath);
        Security.addProvider(this.provider);

        this.keyStore = KeyStore.getInstance("PKCS11", this.provider);
        this.keyStore.load(null, userPin);   // PIN unlocks the token for this session
    }

    public Provider provider() {
        return provider;
    }

    public KeyStore keyStore() {
        return keyStore;
    }

    public String providerName() {
        return provider.getName();
    }

    @Override
    public void close() {
        // SunPKCS11 logs out when the provider is removed; keep registered for the
        // app's lifetime. Nothing to release explicitly here.
    }
}
