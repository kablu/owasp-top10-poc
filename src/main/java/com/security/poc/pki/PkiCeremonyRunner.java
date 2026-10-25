package com.security.poc.pki;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;

/**
 * Standalone runner for the full CA ceremony against SoftHSM — no Spring context.
 * Useful for running the ceremony directly inside WSL (where SoftHSM lives).
 *
 * <pre>
 *   java --add-modules jdk.crypto.cryptoki \
 *        -cp "out:bcprov.jar:bcpkix.jar:bcutil.jar" \
 *        com.security.poc.pki.PkiCeremonyRunner /path/softhsm-pkcs11.cfg 1234
 * </pre>
 *
 * Args: [pkcs11ConfigPath] [userPin]. Defaults: ./softhsm-pkcs11.cfg and 1234.
 */
public final class PkiCeremonyRunner {

    public static void main(String[] args) throws Exception {
        String cfg = args.length > 0 ? args[0] : "softhsm-pkcs11.cfg";
        char[] pin = (args.length > 1 ? args[1] : "1234").toCharArray();

        System.out.println("== Opening SoftHSM via SunPKCS11 (" + cfg + ") ==");
        HsmContext hsm = new HsmContext(cfg, pin);
        System.out.println("Provider: " + hsm.providerName());
        CaCeremonyService ca = new CaCeremonyService(hsm);

        // Start clean: remove any entries from a previous run. Overwriting an
        // existing PKCS#11 alias and reading it back in the same session is
        // unreliable with SunPKCS11, so we delete first and create fresh.
        for (String a : new String[]{"server-ee", "intermediate-ca", "root-ca"}) {
            if (hsm.keyStore().containsAlias(a)) {
                hsm.keyStore().deleteEntry(a);
                System.out.println("Cleared existing HSM entry: " + a);
            }
        }

        System.out.println("\n== 1) Root CA: keypair in HSM + self-sign ==");
        X509Certificate root = ca.createSelfSignedRoot(
                "root-ca", "CN=Demo Root CA,O=PKI Lab,C=IN", 3072, "SHA256withRSA", 20);
        System.out.println("Root subject : " + root.getSubjectX500Principal());
        System.out.println("Root serial  : " + root.getSerialNumber());
        System.out.println(CaCeremonyService.toPem(root));
        Path outDir = Files.createDirectories(Path.of("out"));
        Path rootFile = outDir.resolve("root-ca.cer");
        Files.writeString(rootFile, CaCeremonyService.toPem(root));
        System.out.println("Root cert written to: " + rootFile.toAbsolutePath() + "\n");

        System.out.println("== 2) Intermediate keypair in HSM + PKCS#10 CSR ==");
        PKCS10CertificationRequest csr = ca.createIntermediateCsr(
                "intermediate-ca", "CN=Demo Intermediate CA,O=PKI Lab,C=IN", 2048, "SHA256withRSA");
        System.out.println("CSR subject  : " + csr.getSubject());
        System.out.println(CaCeremonyService.toPem(csr));
        System.out.println("   (In production this CSR is sent to the external CA / CCA India.)\n");

        System.out.println("== 3) Root signs the CSR (role of external CA) ==");
        X509Certificate interCert = ca.signCsr(csr, "root-ca", "SHA256withRSA", 10, 0);
        System.out.println("Issued to    : " + interCert.getSubjectX500Principal());
        System.out.println("Issued by    : " + interCert.getIssuerX500Principal());
        System.out.println(CaCeremonyService.toPem(interCert));
        Path interFile = outDir.resolve("intermediate-ca.cer");
        Files.writeString(interFile, CaCeremonyService.toPem(interCert));
        System.out.println("Intermediate cert written to: " + interFile.toAbsolutePath() + "\n");

        System.out.println("== 4) Bind issued cert to its HSM key + build chain ==");
        X509Certificate[] chain = ca.bindIssuedCert("intermediate-ca", interCert, "root-ca");
        ca.verifyChain(chain);
        System.out.println("Chain length : " + chain.length + "  [intermediate -> root]");
        System.out.println("Chain VERIFIED OK (intermediate signed by root; root self-signed).");
        StringBuilder chainPem = new StringBuilder();
        for (X509Certificate c : chain) chainPem.append(CaCeremonyService.toPem(c));
        Path chainFile = outDir.resolve("chain.pem");
        Files.writeString(chainFile, chainPem.toString());
        System.out.println("Chain written to: " + chainFile.toAbsolutePath());

        System.out.println("\n== 5) End-entity (TLS server) cert issued by the intermediate ==");
        PKCS10CertificationRequest eeCsr = ca.createCsr(
                "server-ee", "CN=localhost,O=PKI Lab,C=IN", 2048, "SHA256withRSA");
        // 825 days ~ max TLS server validity; SAN = localhost (TLS requires SAN).
        X509Certificate eeCert = ca.signEndEntityCsr(
                eeCsr, "intermediate-ca", "SHA256withRSA", 825, "localhost");
        System.out.println("EE subject   : " + eeCert.getSubjectX500Principal());
        System.out.println("EE issuer    : " + eeCert.getIssuerX500Principal());
        System.out.println(CaCeremonyService.toPem(eeCert));

        // Full 3-tier chain: EE -> intermediate -> root
        X509Certificate interForChain = (X509Certificate) hsm.keyStore().getCertificate("intermediate-ca");
        X509Certificate rootForChain = (X509Certificate) hsm.keyStore().getCertificate("root-ca");
        X509Certificate[] fullChain = {eeCert, interForChain, rootForChain};
        ca.verifyChain(fullChain);
        // Bind EE cert to its HSM key with the full chain.
        java.security.PrivateKey eeKey = (java.security.PrivateKey) hsm.keyStore().getKey("server-ee", null);
        hsm.keyStore().setKeyEntry("server-ee", eeKey, null, fullChain);
        System.out.println("3-tier chain VERIFIED OK  [EE -> intermediate -> root]");

        Path eeFile = outDir.resolve("server-ee.cer");
        Files.writeString(eeFile, CaCeremonyService.toPem(eeCert));
        System.out.println("EE leaf cert written to: " + eeFile.toAbsolutePath());
        // Server chain = leaf + intermediate (NO root; clients already trust the root).
        Path serverChain = outDir.resolve("server-chain.pem");
        Files.writeString(serverChain,
                CaCeremonyService.toPem(eeCert) + CaCeremonyService.toPem(interForChain));
        System.out.println("Server chain (leaf+intermediate) written to: " + serverChain.toAbsolutePath());

        System.out.println("\n== HSM token entries ==");
        var ks = hsm.keyStore();
        var aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            System.out.println("  alias=" + a + "  key=" + ks.isKeyEntry(a)
                    + "  subject=" + ((X509Certificate) ks.getCertificate(a)).getSubjectX500Principal());
        }
        System.out.println("\nDone. Keys never left the HSM; all signing ran on the token.");
    }

    private PkiCeremonyRunner() {
    }
}
