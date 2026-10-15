import assert from "node:assert/strict";

import { parseCli } from "./main.ts";

const REQUIRED = [
  "--zone",
  "example.com",
  "--domain",
  "example.com",
  "--email",
  "admin@example.com",
];

Deno.test("CLI keeps the default propagation delay at zero", () => {
  assert.equal(parseCli(REQUIRED).propagationDelayMs, 0);
});

Deno.test("CLI passes the demo propagation delay and total timeout in milliseconds", () => {
  const options = parseCli([
    ...REQUIRED,
    "--propagation-delay",
    "180",
    "--propagation-timeout",
    "600",
  ]);
  assert.equal(options.propagationDelayMs, 180_000);
  assert.equal(options.propagationTimeoutMs, 600_000);
});

Deno.test("CLI rejects negative or nonfinite propagation delays", () => {
  for (const value of ["-1", "NaN", "Infinity"]) {
    assert.throws(
      () => parseCli([...REQUIRED, `--propagation-delay=${value}`]),
      /propagation-delay/,
    );
  }
});

Deno.test("CLI requires a total timeout larger than the propagation delay", () => {
  for (const value of ["300", "301"]) {
    assert.throws(
      () => parseCli([...REQUIRED, "--propagation-delay", value]),
      /propagation-timeout 必须大于 --propagation-delay/,
    );
  }
});
