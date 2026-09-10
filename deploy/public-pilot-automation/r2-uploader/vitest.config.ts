import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

const TEST_HMAC_SECRET = "11".repeat(32);
const TEST_VALIDATOR_HMAC_SECRET = "22".repeat(32);
const TEST_VALIDATOR_SUBMISSION_ID = "bc".repeat(32);
const TEST_VALIDATOR_NAMESPACE = "cd".repeat(16);
const TEST_BOOTSTRAP_INPUT_HMAC_SECRET = "44".repeat(32);

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: "./wrangler.jsonc",
      },
      miniflare: {
        bindings: {
          UPLOAD_HMAC_SECRET: TEST_HMAC_SECRET,
          VALIDATOR_BOOTSTRAP_UPLOAD_HMAC_ALLOWLIST: JSON.stringify({
            [TEST_VALIDATOR_SUBMISSION_ID]: TEST_VALIDATOR_HMAC_SECRET,
          }),
          VALIDATOR_BOOTSTRAP_UPLOAD_HMAC_NAMESPACE_MAP: JSON.stringify({
            [TEST_VALIDATOR_NAMESPACE]: TEST_VALIDATOR_HMAC_SECRET,
          }),
          VALIDATOR_BOOTSTRAP_INPUT_UPLOAD_HMAC_SECRET:
            TEST_BOOTSTRAP_INPUT_HMAC_SECRET,
        },
      },
    }),
  ],
  test: {
    globals: false,
  },
});
