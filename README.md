# Strand DNS Diagnostics

Test DNS-over-HTTPS and DNS-over-TLS directly from your Android device.

Strand DNS sends real DNS queries over the network your phone is using. The report shows how far each check got, from resolving the server address through TCP, TLS, and the DNS exchange, so you can see where a resolver connection fails.

## Features

- Check DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) individually or side by side.
- Choose a resolver preset or enter your own endpoint.
- Query A, AAAA, TXT, NS, MX, HTTPS, and CNAME records.
- Inspect connection timings, DNS response codes, answer records, and TLS certificate details.
- Verify certificates and hostnames by default. An optional diagnostic mode lets you inspect an untrusted resolver.
- Review recent checks and choose System default, Light, or Dark appearance.

Probes run on the device, and recent checks are stored locally. Strand DNS requires no account or remote relay.

## Build from source

The app requires Android 7.0 or later. To build it, use JDK 17 and Android SDK Platform 34. Open the project in Android Studio or run the included Gradle wrapper:

```sh
./gradlew assembleDebug
```

The debug APK is written to `app/build/outputs/apk/debug/app-debug.apk`. The Android package ID is `app.strand.dns`.

## Typography

The app bundles [Hack](https://github.com/source-foundry/Hack). Its license and upstream notices are included in [Hack-LICENSE.txt](app/src/main/assets/fonts/Hack-LICENSE.txt).

## Release builds

GitHub Actions builds the app on pushes and pull requests. A version tag such
as `v1.0.0` also publishes a release APK after signing. The release job reads
its keystore and credentials from the repository's Actions secrets:
`STRAND_KEYSTORE_BASE64`, `STRAND_KEYSTORE_PASSWORD`, `STRAND_KEY_ALIAS`, and
`STRAND_KEY_PASSWORD`. Keep the same release key and increment `versionCode`
for every published version.

## License

The Strand DNS Diagnostics app source is licensed under the
[GNU Affero General Public License, version 3 only](LICENSE) (`AGPL-3.0-only`).
Bundled Hack font files remain subject to their [upstream license](app/src/main/assets/fonts/Hack-LICENSE.txt).
