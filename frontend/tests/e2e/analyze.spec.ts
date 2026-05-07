import { test, expect } from "@playwright/test";

const BENIGN_COMMAND = "ls -la /tmp";

test.describe("paste → redirect → render flow", () => {
  test("submitting a command redirects to /c/[slug] and renders the analysis", async ({
    page,
  }) => {
    // Mock the backend POST /analyze so the test doesn't require a live backend
    await page.route("**/analyze", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          slug: "AAAAAAAAABBB",
          command: BENIGN_COMMAND,
          parsed: { kind: "command", pos: [0, 12], parts: [] },
          parsed_error: null,
          decoded_layers: [],
          lolbas_match: null,
        }),
      });
    });

    // Mock the backend GET /c/:slug so the SSR page can render
    await page.route("**/c/AAAAAAAAABBB", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          slug: "AAAAAAAAABBB",
          command: BENIGN_COMMAND,
          parsed: { kind: "command", pos: [0, 12], parts: [] },
          parsed_error: null,
          decoded_layers: [],
          lolbas_match: null,
        }),
      });
    });

    await page.goto("/");

    // The textarea should be visible
    const textarea = page.getByTestId("command-input");
    await expect(textarea).toBeVisible();

    // Type the command
    await textarea.fill(BENIGN_COMMAND);

    // Submit the form
    await page.getByRole("button", { name: /analyze/i }).click();

    // Should redirect to /c/[slug]
    await page.waitForURL("**/c/AAAAAAAAABBB", { timeout: 10_000 });
    expect(page.url()).toContain("/c/AAAAAAAAABBB");

    // Slug should appear in the heading
    await expect(page.getByText(/\/c\/AAAAAAAAABBB/)).toBeVisible();
  });

  test("slug URL matches base32 pattern (12 uppercase alphanum chars)", async ({
    page,
  }) => {
    // Intercept and return a realistic slug
    await page.route("**/analyze", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          slug: "MFRA2YLBMFRA",
          command: BENIGN_COMMAND,
          parsed: null,
          parsed_error: null,
          decoded_layers: [],
          lolbas_match: null,
        }),
      });
    });

    await page.goto("/");
    await page.getByTestId("command-input").fill(BENIGN_COMMAND);
    await page.getByRole("button", { name: /analyze/i }).click();

    await page.waitForURL(/\/c\/[A-Z2-7]{12}/, { timeout: 10_000 });
    const url = page.url();
    const match = url.match(/\/c\/([A-Z2-7]{12})/);
    expect(match).not.toBeNull();
  });
});
