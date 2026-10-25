package com.security.poc.pki;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * REST front-end for the SoftHSM-backed CA ceremony. Each call maps to one step
 * of the real-world flow (keygen → self-signed root → CSR → issue → bind chain).
 *
 * <p>Requires the JVM to run where SoftHSM's native library is reachable (WSL).
 * On a Windows JVM the HSM open will fail with a clear message — run the app in
 * WSL, or use {@link PkiCeremonyRunner} directly.
 *
 * <pre>
 *   POST /pki/root/create
 *   POST /pki/intermediate/csr
 *   POST /pki/intermediate/sign        (uses the CSR from the previous step)
 *   POST /pki/chain/build
 *   GET  /pki/entries
 * </pre>
 */
@RestController
@RequestMapping("/pki")
public class PkiController {

    @Value("${pki.pkcs11.config:/mnt/c/eclipse-workspace/owasp-top10-poc/softhsm-pkcs11.cfg}")
    private String pkcs11Config;

    @Value("${pki.pkcs11.pin:1234}")
    private String userPin;

    private static final String ROOT_ALIAS = "root-ca";
    private static final String INTER_ALIAS = "intermediate-ca";

    private HsmContext hsm;
    private CaCeremonyService ca;

    // Kept between calls so the REST flow can run step by step.
    private PKCS10CertificationRequest lastCsr;
    private X509Certificate lastIssued;

    private synchronized CaCeremonyService ca() throws Exception {
        if (ca == null) {
            hsm = new HsmContext(pkcs11Config, userPin.toCharArray());
            ca = new CaCeremonyService(hsm);
        }
        return ca;
    }

    @PostMapping(value = "/root/create", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> createRoot() {
        return wrap(() -> {
            X509Certificate root = ca().createSelfSignedRoot(
                    ROOT_ALIAS, "CN=Demo Root CA,O=PKI Lab,C=IN", 3072, "SHA256withRSA", 20);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("step", "1/4 root CA created (keypair in HSM, self-signed)");
            out.put("subject", root.getSubjectX500Principal().toString());
            out.put("serial", root.getSerialNumber().toString(16));
            out.put("pem", CaCeremonyService.toPem(root));
            return out;
        });
    }

    @PostMapping(value = "/intermediate/csr", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> createIntermediateCsr() {
        return wrap(() -> {
            lastCsr = ca().createIntermediateCsr(
                    INTER_ALIAS, "CN=Demo Intermediate CA,O=PKI Lab,C=IN", 2048, "SHA256withRSA");
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("step", "2/4 intermediate keypair in HSM + CSR (send this to the external CA)");
            out.put("subject", lastCsr.getSubject().toString());
            out.put("csrPem", CaCeremonyService.toPem(lastCsr));
            return out;
        });
    }

    /** Optional body = CSR PEM; if absent, uses the CSR from the previous step. */
    @PostMapping(value = "/intermediate/sign", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> signCsr(@RequestBody(required = false) String csrPem) {
        return wrap(() -> {
            PKCS10CertificationRequest csr = (csrPem != null && !csrPem.isBlank())
                    ? CaCeremonyService.csrFromPem(csrPem) : lastCsr;
            if (csr == null) {
                throw new IllegalStateException("No CSR available — call /pki/intermediate/csr first.");
            }
            lastIssued = ca().signCsr(csr, ROOT_ALIAS, "SHA256withRSA", 10, 0);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("step", "3/4 Root signed the CSR (role of external CA / CCA India)");
            out.put("subject", lastIssued.getSubjectX500Principal().toString());
            out.put("issuer", lastIssued.getIssuerX500Principal().toString());
            out.put("pem", CaCeremonyService.toPem(lastIssued));
            return out;
        });
    }

    @PostMapping(value = "/chain/build", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> buildChain() {
        return wrap(() -> {
            if (lastIssued == null) {
                throw new IllegalStateException("No issued cert — call /pki/intermediate/sign first.");
            }
            X509Certificate[] chain = ca().bindIssuedCert(INTER_ALIAS, lastIssued, ROOT_ALIAS);
            ca().verifyChain(chain);
            StringBuilder pem = new StringBuilder();
            for (X509Certificate c : chain) pem.append(CaCeremonyService.toPem(c));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("step", "4/4 issued cert bound to its HSM key; chain verified");
            out.put("chainLength", chain.length);
            out.put("verified", true);
            out.put("chainPem", pem.toString());
            return out;
        });
    }

    @GetMapping(value = "/entries", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> entries() {
        return wrap(() -> {
            ca();                      // ensure the HSM context is open
            var ks = hsm.keyStore();
            Map<String, Object> out = new LinkedHashMap<>();
            var aliases = ks.aliases();
            Map<String, String> items = new LinkedHashMap<>();
            while (aliases.hasMoreElements()) {
                String a = aliases.nextElement();
                X509Certificate c = (X509Certificate) ks.getCertificate(a);
                items.put(a, (ks.isKeyEntry(a) ? "key+cert: " : "cert: ")
                        + (c != null ? c.getSubjectX500Principal().toString() : "(none)"));
            }
            out.put("entries", items);
            return out;
        });
    }

    private interface Step {
        Map<String, Object> run() throws Exception;
    }

    private Map<String, Object> wrap(Step step) {
        try {
            return step.run();
        } catch (Exception e) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
            err.put("hint", "Run the app inside WSL so the Linux SoftHSM library is reachable, "
                    + "ensure the token is initialized, and check pki.pkcs11.config / pki.pkcs11.pin.");
            return err;
        }
    }
}
