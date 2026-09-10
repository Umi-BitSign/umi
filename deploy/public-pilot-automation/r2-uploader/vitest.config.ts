import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

const TEST_HMAC_SECRET = "11".repeat(32);
const TEST_VALIDATOR_HMAC_SECRET = "22".repeat(32);

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: "./wrangler.jsonc",
      },
      miniflare: {
        bindings: {
          UPLOAD_HMAC_SECRET: TEST_HMAC_SECRET,
          VALIDATOR_BOOTSTRAP_UPLOAD_HMAC_SECRET: TEST_VALIDATOR_HMAC_SECRET,
        },
      },
    }),
  ],
  test: {
    globals: false,
  },
});
