// Non-interactive setup tests keep provisioning and output on the configured default agent.
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { OpenClawConfig } from "../../config/types.openclaw.js";
import type { RuntimeEnv } from "../../runtime.js";

const mocks = vi.hoisted(() => ({
  commitConfig: vi.fn(),
  ensureWorkspaceAndSessions: vi.fn(),
  logConfigUpdated: vi.fn(),
  logJson: vi.fn(),
}));

vi.mock("../../config/config.js", () => ({
  resolveGatewayPort: () => 18789,
}));

vi.mock("../../config/logging.js", () => ({
  logConfigUpdated: mocks.logConfigUpdated,
}));

vi.mock("../onboard-helpers.js", () => ({
  DEFAULT_WORKSPACE: "/tmp/default-workspace",
  applyWizardMetadata: (config: OpenClawConfig) => config,
  ensureWorkspaceAndSessions: mocks.ensureWorkspaceAndSessions,
  resolveLocalControlUiProbeLinks: vi.fn(),
  waitForGatewayReachable: vi.fn(),
}));

vi.mock("./config-write.js", () => ({
  commitNonInteractiveOnboardConfig: mocks.commitConfig,
}));

vi.mock("./local/gateway-config.js", () => ({
  applyNonInteractiveGatewayConfig: ({ nextConfig }: { nextConfig: OpenClawConfig }) => ({
    nextConfig,
    port: 18789,
    bind: "loopback",
    authMode: "token",
    tailscaleMode: "off",
  }),
}));

vi.mock("./local/output.js", () => ({
  logNonInteractiveOnboardingFailure: vi.fn(),
  logNonInteractiveOnboardingJson: mocks.logJson,
}));

vi.mock("./local/skills-config.js", () => ({
  applyNonInteractiveSkillsConfig: ({ nextConfig }: { nextConfig: OpenClawConfig }) => nextConfig,
}));

import { runNonInteractiveLocalSetup } from "./local.js";

const runtime = {
  log: vi.fn(),
  error: vi.fn(),
  exit: vi.fn(),
} as unknown as RuntimeEnv;

describe("runNonInteractiveLocalSetup default-agent ownership", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.commitConfig.mockImplementation(
      async ({ nextConfig }: { nextConfig: OpenClawConfig }) => nextConfig,
    );
  });

  it("targets the selected keyed agent when --workspace matches the inherited default", async () => {
    const baseConfig = {
      agents: {
        defaults: { workspace: "/tmp/global-workspace" },
        entries: {
          ops: {
            default: true,
            agentDir: "/tmp/ops-agent",
            workspace: "/tmp/ops-workspace",
          },
        },
      },
    } satisfies OpenClawConfig;

    await runNonInteractiveLocalSetup({
      opts: {
        nonInteractive: true,
        mode: "local",
        workspace: "/tmp/global-workspace",
        authChoice: "skip",
        skipHooks: true,
        skipSkills: true,
        skipHealth: true,
        installDaemon: false,
        json: true,
      },
      runtime,
      baseConfig,
    });

    expect(mocks.commitConfig).toHaveBeenCalledWith(
      expect.objectContaining({
        nextConfig: expect.objectContaining({
          agents: expect.objectContaining({
            defaults: expect.objectContaining({ workspace: "/tmp/global-workspace" }),
            entries: expect.objectContaining({
              ops: expect.objectContaining({ workspace: "/tmp/global-workspace" }),
            }),
          }),
        }),
      }),
    );
    expect(mocks.ensureWorkspaceAndSessions).toHaveBeenCalledWith(
      "/tmp/global-workspace",
      runtime,
      expect.objectContaining({ agentId: "ops" }),
    );
    expect(mocks.logJson).toHaveBeenCalledWith(
      expect.objectContaining({ workspaceDir: "/tmp/global-workspace" }),
    );
  });

  it("rejects changing an include-owned selected agent workspace", async () => {
    await expect(
      runNonInteractiveLocalSetup({
        opts: {
          nonInteractive: true,
          mode: "local",
          agent: "ops",
          workspace: "/tmp/new-ops-workspace",
          authChoice: "skip",
          skipHooks: true,
          skipSkills: true,
          skipHealth: true,
          installDaemon: false,
        },
        runtime,
        agentRosterIncludeOwned: true,
        baseConfig: {
          agents: {
            ownership: "explicit",
            entries: {
              ops: { workspace: "/tmp/ops-workspace" },
              research: {},
            },
          },
        },
      }),
    ).rejects.toThrow(
      "Cannot set agents.entries.ops.workspace because the agent roster is $include-owned",
    );
    expect(mocks.commitConfig).not.toHaveBeenCalled();
  });
});
