#!/bin/sh
set -e
cd "$(dirname "$0")/.."
rm -rf tools/out
mkdir -p tools/out
javac --release 17 -encoding UTF-8 -d tools/out \
  app/src/main/java/app/strand/dns/Models.java \
  app/src/main/java/app/strand/dns/Iso.java \
  app/src/main/java/app/strand/dns/DnsCodec.java \
  app/src/main/java/app/strand/dns/Endpoints.java \
  app/src/main/java/app/strand/dns/Present.java \
  app/src/main/java/app/strand/dns/Probe.java \
  tools/SelfTest.java
java -cp tools/out app.strand.dns.SelfTest
