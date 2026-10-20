import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import { seedAccount } from "./seed-account.mjs";

async function server(handler) {
  const instance = http.createServer(handler);
  await new Promise(resolve => instance.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${instance.address().port}`,
    close: () => new Promise(resolve => { instance.closeAllConnections(); instance.close(resolve); }),
  };
}

for (const phase of ["legacy registration", "verification", "registration finish"]) {
  test(`fixture ${phase} never replays credentials to a redirect destination`, async () => {
    let destinationRequests = 0;
    const destination = await server((request, response) => {
      destinationRequests++;
      request.resume();
      response.end();
    });
    const origin = await server((request, response) => {
      request.resume();
      const stage = request.url === "/api/accounts/register" ? "legacy registration"
        : request.url.endsWith("send-verification-email") ? "verification" : "registration finish";
      if (stage === phase) {
        response.writeHead(stage === "verification" ? 307 : 308, { location: destination.url });
        response.end();
      } else if (stage === "legacy registration") {
        response.writeHead(404);
        response.end();
      } else if (stage === "verification") {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify("synthetic-verification-proof"));
      } else {
        response.end();
      }
    });
    try {
      await assert.rejects(seedAccount(origin.url, "redirect-fixture@example.test", "synthetic-fixture-password"));
      assert.equal(destinationRequests, 0);
    } finally {
      await origin.close();
      await destination.close();
    }
  });
}
