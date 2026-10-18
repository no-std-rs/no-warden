#!/usr/bin/env node
/** Disposable loopback TLS termination for unmodified HTTPS-only CLI releases. */
import { readFileSync } from "node:fs";
import { createServer } from "node:https";
import { request } from "node:http";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const [upstreamUrl, directory] = process.argv.slice(2);
const upstream = new URL(upstreamUrl);
if (upstream.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(upstream.hostname)) {
  throw new Error("The test TLS proxy only forwards to loopback HTTP servers.");
}
const cert = join(directory, "localhost.crt");
const key = join(directory, "localhost.key");
const generated = spawnSync("openssl", [
  "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
  "-subj", "/CN=no-warden disposable compatibility test",
  "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
  "-keyout", key, "-out", cert,
], { stdio: "ignore" });
if (generated.status !== 0) throw new Error("openssl could not generate the disposable test certificate.");

const server = createServer({ cert: readFileSync(cert), key: readFileSync(key) }, (incoming, outgoing) => {
  const destination = new URL(incoming.url, upstream);
  if (destination.origin !== upstream.origin) {
    outgoing.writeHead(400);
    outgoing.end("Invalid test proxy destination");
    return;
  }
  const forwarded = request(destination, {
    method: incoming.method, headers: { ...incoming.headers, host: upstream.host },
  }, response => {
    outgoing.writeHead(response.statusCode, response.headers);
    response.pipe(outgoing);
  });
  forwarded.on("error", () => {
    if (!outgoing.headersSent) outgoing.writeHead(502);
    outgoing.end("Test upstream is unavailable");
  });
  incoming.pipe(forwarded);
});
server.listen(0, "127.0.0.1", () => {
  process.send?.({ url: `https://127.0.0.1:${server.address().port}`, cert });
});
process.on("disconnect", () => server.close(() => process.exit(0)));
process.on("SIGTERM", () => server.close(() => process.exit(0)));
