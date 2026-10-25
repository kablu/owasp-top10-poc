package com.security.poc.pki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * The CA ceremony, done with BouncyCastle and keys that live in SoftHSM.
 *
 * <p>Models the real-world flow used with an external CA (e.g. submitting a CSR
 * to CCA India and getting a signed certificate back):
 * <ol>
 *   <li><b>Root CA</b> — generate the root keypair in the HSM and self-sign it.</li>
 *   <li><b>Intermediate keypair</b> — generated in the HSM; a <b>PKCS#10 CSR</b>
 *       is produced and signed by the intermediate key (proof of possession).</li>
 *   <li><b>Issue</b> — the CSR is signed by the Root (here the Root plays the role
 *       of the external CA). In production this is where you ship the CSR out and
 *       receive the signed certificate.</li>
 *   <li><b>Bind &amp; chain</b> — the returned certificate is stored back into the
 *       HSM under the <b>same alias as its private key</b>, with the issuer cert,
 *       forming a verifiable chain.</li>
 * </ol>
 *
 * <p>All signing uses a {@link ContentSigner} whose provider is SunPKCS11, so the
 * private-key operations run inside the token; keys never leave the HSM.
 * This class has no Spring dependencies so it can run from a REST controller or a
 * plain {@code main}.
 */
public class CaCeremonyService {

    private final HsmContext hsm;
    private final SecureRandom random = new SecureRandom();

    public CaCeremonyService(HsmContext hsm) {
        this.hsm = hsm;
    }

    // ------------------------------------------------------------------
    // 1. Root CA — keypair in HSM, self-signed.
    // ------------------------------------------------------------------
    public X509Certificate createSelfSignedRoot(String alias, String subjectDn,
                                                int keySize, String sigAlg, int validityYears) throws Exception {
        KeyPair kp = generateKeyPairInHsm(keySize);
        X500Name name = new X500Name(subjectDn);
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name,                       // issuer == subject (self-signed)
                randomSerial(),
                from(), until(validityYears),
                name,
                kp.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                ext.createSubjectKeyIdentifier(kp.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                ext.createAuthorityKeyIdentifier(kp.getPublic()));   // self

        // Sign IN the HSM: private-key op runs on the token via SunPKCS11.
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(hsm.providerName())
                .build(kp.getPrivate());

        X509Certificate root = toCert(builder.build(signer));

        // Persist the key + its self-signed cert as a token entry under `alias`.
        hsm.keyStore().setKeyEntry(alias, kp.getPrivate(), null, new Certificate[]{root});
        return root;
    }

    // ------------------------------------------------------------------
    // 2. Intermediate keypair in HSM + PKCS#10 CSR (proof of possession).
    //    A temporary self-signed cert is stored so the key persists in the
    //    token between the CSR and the later "bind issued cert" step.
    // ------------------------------------------------------------------
    public PKCS10CertificationRequest createIntermediateCsr(String alias, String subjectDn,
                                                            int keySize, String sigAlg) throws Exception {
        return createCsr(alias, subjectDn, keySize, sigAlg);
    }

    /**
     * Generate a keypair in the HSM under {@code alias} and produce a PKCS#10 CSR
     * signed by that key (proof of possession). A temporary self-signed cert is
     * stored so the private key persists in the token between the CSR and the
     * later "bind issued cert" step. Used for intermediate and end-entity alike.
     */
    public PKCS10CertificationRequest createCsr(String alias, String subjectDn,
                                                int keySize, String sigAlg) throws Exception {
        KeyPair kp = generateKeyPairInHsm(keySize);
        X500Name name = new X500Name(subjectDn);

        JcaX509v3CertificateBuilder tmp = new JcaX509v3CertificateBuilder(
                name, randomSerial(), from(), until(1), name, kp.getPublic());
        ContentSigner tmpSigner = new JcaContentSignerBuilder(sigAlg)
                .setProvider(hsm.providerName()).build(kp.getPrivate());
        X509Certificate placeholder = toCert(tmp.build(tmpSigner));
        hsm.keyStore().setKeyEntry(alias, kp.getPrivate(), null, new Certificate[]{placeholder});

        JcaPKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(name, kp.getPublic());
        ContentSigner csrSigner = new JcaContentSignerBuilder(sigAlg)
                .setProvider(hsm.providerName()).build(kp.getPrivate());
        return csrBuilder.build(csrSigner);
    }

    // ------------------------------------------------------------------
    // Issue an END-ENTITY (leaf) certificate — e.g. a TLS server cert —
    // signed by the intermediate. Unlike a CA cert: BasicConstraints CA:FALSE,
    // KeyUsage digitalSignature+keyEncipherment, EKU serverAuth, and a DNS SAN
    // (modern TLS ignores CN and requires the name in subjectAltName).
    // ------------------------------------------------------------------
    public X509Certificate signEndEntityCsr(PKCS10CertificationRequest csr, String issuerAlias,
                                            String sigAlg, int validityDays, String dnsName) throws Exception {
        PrivateKey issuerKey = (PrivateKey) hsm.keyStore().getKey(issuerAlias, null);
        X509Certificate issuerCert = (X509Certificate) hsm.keyStore().getCertificate(issuerAlias);
        if (issuerKey == null || issuerCert == null) {
            throw new IllegalStateException("Issuer '" + issuerAlias + "' not found in HSM");
        }

        JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr);
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                .build(jcaCsr.getPublicKey());
        if (!csr.isSignatureValid(verifier)) {
            throw new SecurityException("CSR signature invalid — proof of possession failed");
        }

        PublicKey subjectKey = jcaCsr.getPublicKey();
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded()),
                randomSerial(),
                from(), untilDays(validityDays),
                csr.getSubject(),
                subjectKey);

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false)); // CA:FALSE
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                ext.createSubjectKeyIdentifier(subjectKey));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                ext.createAuthorityKeyIdentifier(issuerCert.getPublicKey()));
        addRevocationExtensions(builder, issuerAlias);   // CDP + AIA

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(hsm.providerName())
                .build(issuerKey);
        return toCert(builder.build(signer));
    }

    // ------------------------------------------------------------------
    // 3. Issue: the issuer (Root — standing in for the external CA / CCA) signs
    //    the CSR and returns the intermediate certificate.
    // ------------------------------------------------------------------
    public X509Certificate signCsr(PKCS10CertificationRequest csr, String issuerAlias,
                                   String sigAlg, int validityYears, int pathLen) throws Exception {
        PrivateKey issuerKey = (PrivateKey) hsm.keyStore().getKey(issuerAlias, null);
        X509Certificate issuerCert = (X509Certificate) hsm.keyStore().getCertificate(issuerAlias);
        if (issuerKey == null || issuerCert == null) {
            throw new IllegalStateException("Issuer '" + issuerAlias + "' not found in HSM");
        }

        // Verify the CSR's self-signature (proof the requester holds the key).
        JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr);
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                .build(jcaCsr.getPublicKey());
        if (!csr.isSignatureValid(verifier)) {
            throw new SecurityException("CSR signature invalid — proof of possession failed");
        }

        PublicKey subjectKey = jcaCsr.getPublicKey();
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded()),
                randomSerial(),
                from(), until(validityYears),
                csr.getSubject(),
                subjectKey);

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLen));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                ext.createSubjectKeyIdentifier(subjectKey));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                ext.createAuthorityKeyIdentifier(issuerCert.getPublicKey()));
        addRevocationExtensions(builder, issuerAlias);   // CDP + AIA

        // Signed by the issuer's HSM key.
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(hsm.providerName())
                .build(issuerKey);
        return toCert(builder.build(signer));
    }

    // ------------------------------------------------------------------
    // 4. Bind the issued cert back to its HSM key and build the chain.
    // ------------------------------------------------------------------
    public X509Certificate[] bindIssuedCert(String alias, X509Certificate issued,
                                            String issuerAlias) throws Exception {
        PrivateKey subjectKey = (PrivateKey) hsm.keyStore().getKey(alias, null);
        X509Certificate issuerCert = (X509Certificate) hsm.keyStore().getCertificate(issuerAlias);
        if (subjectKey == null) {
            throw new IllegalStateException("Private key for '" + alias + "' not found in HSM");
        }
        X509Certificate[] chain = {issued, issuerCert};
        // Re-store under the same alias, now with the real issued chain.
        hsm.keyStore().setKeyEntry(alias, subjectKey, null, chain);
        return chain;
    }

    /** Cryptographically verify a chain: each cert signed by the next; root self-signed. */
    public void verifyChain(X509Certificate[] chain) throws Exception {
        for (int i = 0; i < chain.length - 1; i++) {
            chain[i].verify(chain[i + 1].getPublicKey());   // throws if invalid
        }
        X509Certificate root = chain[chain.length - 1];
        root.verify(root.getPublicKey());                   // self-signed root
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------
    // Base URLs for the demo PKI's published CRL / OCSP / CA cert, mirroring what
    // a real CA (e.g. under CCA India) embeds so relying parties can fetch the CRL
    // and do OCSP checks. Point these at your actual PKI endpoints in production.
    private static final String PKI_BASE  = "http://pki.pki-lab.example";
    private static final String OCSP_URL  = "http://ocsp.pki-lab.example";

    /**
     * Add CRL Distribution Point (CDP) and Authority Information Access (AIA)
     * extensions to a certificate. CDP tells a verifier where to download the
     * issuer's CRL; AIA gives the OCSP responder URL and a caIssuers URL to fetch
     * the issuer's own certificate. {@code issuerLabel} names the issuer so the
     * URLs resolve to that CA's CRL / cert.
     */
    private void addRevocationExtensions(JcaX509v3CertificateBuilder builder, String issuerLabel)
            throws Exception {
        String crlUrl = PKI_BASE + "/crl/" + issuerLabel + ".crl";
        String caIssuersUrl = PKI_BASE + "/" + issuerLabel + ".cer";

        // CDP: URI to the issuer's CRL.
        DistributionPointName dpName = new DistributionPointName(
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl)));
        DistributionPoint dp = new DistributionPoint(dpName, null, null);
        builder.addExtension(Extension.cRLDistributionPoints, false,
                new CRLDistPoint(new DistributionPoint[]{dp}));

        // AIA: OCSP responder + caIssuers (where to fetch the issuer cert).
        AccessDescription ocsp = new AccessDescription(AccessDescription.id_ad_ocsp,
                new GeneralName(GeneralName.uniformResourceIdentifier, OCSP_URL));
        AccessDescription caIssuers = new AccessDescription(AccessDescription.id_ad_caIssuers,
                new GeneralName(GeneralName.uniformResourceIdentifier, caIssuersUrl));
        builder.addExtension(Extension.authorityInfoAccess, false,
                new AuthorityInformationAccess(new AccessDescription[]{ocsp, caIssuers}));
    }

    private KeyPair generateKeyPairInHsm(int keySize) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", hsm.provider());
        kpg.initialize(keySize);
        return kpg.generateKeyPair();   // keys created inside the token
    }

    private BigInteger randomSerial() {
        return new BigInteger(159, random);   // positive, ~20 bytes
    }

    private static Date from() {
        return Date.from(Instant.now().minus(1, ChronoUnit.HOURS));
    }

    private static Date until(int years) {
        return Date.from(Instant.now().plus(365L * years, ChronoUnit.DAYS));
    }

    private static Date untilDays(int days) {
        return Date.from(Instant.now().plus(days, ChronoUnit.DAYS));
    }

    private static X509Certificate toCert(X509CertificateHolder holder) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    public static String toPem(Object obj) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(obj);
        }
        return sw.toString();
    }

    public static PKCS10CertificationRequest csrFromPem(String pem) throws Exception {
        try (PemReader reader = new PemReader(new StringReader(pem))) {
            PemObject po = reader.readPemObject();
            return new PKCS10CertificationRequest(po.getContent());
        }
    }
}
