# BCFKS keystore generation

Generates BCFKS counterparts for every JKS/PKCS12 keystore under `src/test/resources/`.
BCFKS (Bouncy Castle FIPS Keystore) files are required when running tests in FIPS approved-only mode.

## Prerequisites

- Java on `PATH`
- `bc-fips-*.jar` — set `BC_FIPS_JAR` to its path before running (see Usage)

## Usage

### Linux / macOS

```bash
export BC_FIPS_JAR=/path/to/bc-fips-2.1.2.jar
./src/test/resources/bcfks-generation/generate_bcfks_keystores.sh
```

### Windows

```bat
set BC_FIPS_JAR=C:\path\to\bc-fips-2.1.2.jar
src\test\resources\bcfks-generation\generate_bcfks_keystores.bat
```

Each `.bcfks` file is written alongside its source keystore. Re-run whenever a source JKS or PKCS12 file is added or regenerated.

## How it works

`ConvertKeystore.java` is compiled on-the-fly against the `bc-fips` JAR and used to copy all key and certificate entries from the source keystore into a new BCFKS store.

When both a `.p12` and a `.jks` share the same base name, only the PKCS12 is used as the source — PKCS12 is the IETF-standardized format and the more faithful input for FIPS-compliant keystores.

`sslConfigurator/` keystores use the password `secret` instead of the default `changeit`.
