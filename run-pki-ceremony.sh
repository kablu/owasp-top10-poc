#!/usr/bin/env bash
# Run the SoftHSM CA ceremony. MUST run inside WSL (Linux) — SoftHSM's native
# library is a Linux .so, so a Windows JVM cannot load it and the Windows
# SunPKCS11 also rejects a /usr/... path as "not absolute".
#
# Usage (from a WSL/Ubuntu shell):
#   cd /mnt/c/eclipse-workspace/owasp-top10-poc
#   ./run-pki-ceremony.sh                 # defaults: softhsm-pkcs11.cfg, PIN 1234
#   ./run-pki-ceremony.sh <cfg> <pin>
set -euo pipefail

if grep -qiv microsoft /proc/version 2>/dev/null; then
  echo "WARNING: this does not look like WSL. SoftHSM-in-WSL needs a Linux JVM." >&2
fi

CFG="${1:-softhsm-pkcs11.cfg}"
PIN="${2:-1234}"

# Pick a Linux JVM: the no-sudo Temurin in ~/jdk21, else whatever is on PATH.
if [ -x "$HOME/jdk21/bin/java" ]; then
  JAVA="$HOME/jdk21/bin/java"
elif command -v java >/dev/null 2>&1; then
  JAVA="$(command -v java)"
else
  echo "ERROR: no Linux java found. Install one, e.g. extract Temurin 21 to ~/jdk21." >&2
  exit 1
fi

# Ensure the classes are built (built on Windows is fine — bytecode is portable).
CLASSES="build/classes/java/main"
if [ ! -f "$CLASSES/com/security/poc/pki/PkiCeremonyRunner.class" ]; then
  echo "ERROR: $CLASSES not found. Build first on Windows: gradlew compileJava" >&2
  exit 1
fi

# Locate the BouncyCastle jars in the Gradle cache (Windows or Linux home).
find_jar() {
  local name="$1" hit=""
  for base in "/mnt/c/Users/Kablu/.gradle/caches" "$HOME/.gradle/caches"; do
    [ -d "$base" ] || continue
    hit="$(find "$base" -name "$name" 2>/dev/null | head -1)"
    [ -n "$hit" ] && { echo "$hit"; return 0; }
  done
  echo "ERROR: $name not found in Gradle cache." >&2
  return 1
}
PROV="$(find_jar 'bcprov-jdk18on-1.78.1.jar')"
PKIX="$(find_jar 'bcpkix-jdk18on-1.78.1.jar')"
UTIL="$(find_jar 'bcutil-jdk18on-1.78.1.jar')"

CP="$CLASSES:$PROV:$PKIX:$UTIL"
echo "JVM : $JAVA"
echo "CFG : $CFG   PIN: $PIN"
echo "----"
exec "$JAVA" --add-modules jdk.crypto.cryptoki -cp "$CP" \
     com.security.poc.pki.PkiCeremonyRunner "$CFG" "$PIN"
