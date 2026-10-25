package com.security.poc.pki;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Cross-certification (cross-CA signing) demo — the eMudhra / Sectigo pattern.
 *
 * <p><b>What cross-signing is:</b> the SAME intermediate CA key pair (same subject
 * DN, same public key, one private key in the HSM) is given TWO certificates by
 * TWO independent roots. One cert is signed by the CA's own root (native chain);
 * the other — the <b>cross certificate</b> — is signed by a second, already widely
 * trusted root. End-entity certs issued by that intermediate then chain to
 * <b>either</b> root, so relying parties that trust only the second root still
 * trust the leaf. The private key never changes; only an extra cert is bound to it.
 *
 * <pre>
 *   eMudhra Root ---signs--> [eMudhra Sub CA]  (cert A, native)
 *   Sectigo Root ---signs--> [eMudhra Sub CA]  (cert B, CROSS — same key+subject)
 *                                   |
 *                                 signs
 *                                   v
 *                             leaf (one cert)
 *
 *   leaf verifies via:  leaf -> certA -> eMudhra Root
 *                 and:  leaf -> certB -> Sectigo Root
 * </pre>
 */
public final class CrossSignRunner {

    public static void main(String[] args) throws Exception {
        String cfg = args.length > 0 ? args[0] : "softhsm-pkcs11.cfg";
        char[] pin = (args.length > 1 ? args[1] : "1234").toCharArray();

        HsmContext hsm = new HsmContext(cfg, pin);
        CaCeremonyService ca = new CaCeremonyService(hsm);
        Path out = Files.createDirectories(Path.of("out-cross"));

        // Clean previous run.
        for (String a : new String[]{"ee-cross", "emudhra-intermediate", "emudhra-root", "sectigo-root"}) {
            if (hsm.keyStore().containsAlias(a)) hsm.keyStore().deleteEntry(a);
        }

        System.out.println("== Two independent self-signed roots ==");
        X509Certificate emudhraRoot = ca.createSelfSignedRoot(
                "emudhra-root", "CN=eMudhra Demo Root,O=eMudhra,C=IN", 3072, "SHA256withRSA", 20);
        X509Certificate sectigoRoot = ca.createSelfSignedRoot(
                "sectigo-root", "CN=Sectigo Demo Root,O=Sectigo,C=GB", 3072, "SHA256withRSA", 20);
        write(out, "emudhra-root.cer", emudhraRoot);
        write(out, "sectigo-root.cer", sectigoRoot);

        System.out.println("\n== eMudhra Intermediate: ONE keypair in HSM, ONE CSR ==");
        PKCS10CertificationRequest interCsr = ca.createCsr(
                "emudhra-intermediate", "CN=eMudhra Demo Sub CA,O=eMudhra,C=IN", 2048, "SHA256withRSA");

        System.out.println("== Native cert A: eMudhra Root signs the CSR ==");
        X509Certificate certNative = ca.signCsr(interCsr, "emudhra-root", "SHA256withRSA", 10, 0);
        System.out.println("  subject=" + certNative.getSubjectX500Principal());
        System.out.println("  issuer =" + certNative.getIssuerX500Principal());

        System.out.println("== CROSS cert B: Sectigo Root signs the SAME CSR ==");
        X509Certificate certCross = ca.signCsr(interCsr, "sectigo-root", "SHA256withRSA", 10, 0);
        System.out.println("  subject=" + certCross.getSubjectX500Principal());
        System.out.println("  issuer =" + certCross.getIssuerX500Principal());
        System.out.println("  SAME subject as cert A?    "
                + certNative.getSubjectX500Principal().equals(certCross.getSubjectX500Principal()));
        System.out.println("  SAME public key as cert A? "
                + Arrays.equals(certNative.getPublicKey().getEncoded(),
                                certCross.getPublicKey().getEncoded()));
        write(out, "intermediate-native.cer", certNative);
        write(out, "intermediate-cross.cer", certCross);

        // Bind the native chain to the intermediate's EXISTING HSM key (setKeyEntry).
        // In production, when the cross cert (B) arrives from the other CA, it is
        // bound to the SAME private key (same CKA_ID) as an alternate certificate.
        PrivateKey interKey = (PrivateKey) hsm.keyStore().getKey("emudhra-intermediate", null);
        hsm.keyStore().setKeyEntry("emudhra-intermediate", interKey, null,
                new X509Certificate[]{certNative, emudhraRoot});
        System.out.println("Bound native chain to the intermediate's existing HSM key (private key unchanged).");

        System.out.println("\n== Leaf issued by the eMudhra Intermediate (one key signs it) ==");
        PKCS10CertificationRequest eeCsr = ca.createCsr(
                "ee-cross", "CN=www.demo.example,O=Customer,C=IN", 2048, "SHA256withRSA");
        X509Certificate leaf = ca.signEndEntityCsr(
                eeCsr, "emudhra-intermediate", "SHA256withRSA", 825, "www.demo.example");
        write(out, "leaf.cer", leaf);

        // The SAME leaf, two chains — pick whichever root the relying party trusts.
        Files.writeString(out.resolve("chain-via-emudhra.pem"),
                CaCeremonyService.toPem(leaf) + CaCeremonyService.toPem(certNative));
        Files.writeString(out.resolve("chain-via-sectigo.pem"),
                CaCeremonyService.toPem(leaf) + CaCeremonyService.toPem(certCross));

        // Verify both paths cryptographically.
        ca.verifyChain(new X509Certificate[]{leaf, certNative, emudhraRoot});
        ca.verifyChain(new X509Certificate[]{leaf, certCross, sectigoRoot});
        System.out.println("\nBOTH paths VERIFIED:");
        System.out.println("  leaf -> intermediate(certA) -> eMudhra Root   OK");
        System.out.println("  leaf -> intermediate(certB) -> Sectigo Root   OK");
        System.out.println("Files in out-cross/. Same leaf, same intermediate key, two trust anchors.");
    }

    private static void write(Path dir, String name, X509Certificate cert) throws Exception {
        Files.writeString(dir.resolve(name), CaCeremonyService.toPem(cert));
    }

    private CrossSignRunner() {
    }
}
