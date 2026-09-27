import type {
  AccessProfile,
  ConformanceReport,
  HarnessCapabilityProfile,
  HarnessEvent,
  HarnessManifest,
  HarnessRunSpec,
} from "@claudexor/schema";
import {
  ConformanceReport as ConformanceReportSchema,
  credentialProfilePolicyForPlatform,
  credentialTransportsForPlatform,
  HarnessCapabilityProfile as HarnessCapabilityProfileSchema,
  HarnessManifest as HarnessManifestSchema,
} from "@claudexor/schema";
import type { DoctorSpec, HarnessAdapter } from "@claudexor/core";
import {
  HarnessUnavailableError,
  harnessPlatform,
  needsPrivatePerProfileKeychain,
  promptWithInstructions,
  runCapture,
  runCliHarness,
} from "@claudexor/core";
import { CLAUDEXOR_VERSION, nowIso, redactSecrets } from "@claudexor/util";
import { parseAgyEvent } from "./parse.js";
import { isAgyProfileKeychainUnsafe, prepareAgyProfileKeychain } from "./keychain.js";
import {
  AGY_BIN,
  defaultAgyModelProbe,
  probeAgyCredentialProfile,
  resolveAgyProfileRoute,
} from "./profile.js";
import { AGY_VENDOR_CLI_VERSION } from "./vendor-cli-version.js";
// The package publishes only what other packages consume. The profile probe,
// the route resolver and the stream parser are reached through the adapter
// this file returns, so re-exporting them would be a dead public surface.
export { AGY_BIN, agyProfileRunEnv, canonicalAgyProfileHome } from "./profile.js";
export { isAgyProfileKeychainUnsafe, prepareAgyProfileKeychain } from "./keychain.js";
export {
  classifyAgyPrintResult,
  runAgyPrintCommand,
  type AgyPrintClassification,
} from "./print-command.js";

/**
 * Access mapping, each leg LIVE-PROVEN on agy 1.1.13 (PLAN §1.2 F11, §1.2d):
 * plan mode answered read-only prompts and withheld a requested write;
 * accept-edits wrote into the workspace; --dangerously-skip-permissions wrote
 * and ran commands. Owner decision Л-7 admits full access explicitly.
 */
function accessArgs(access: AccessProfile): string[] {
  switch (access) {
    case "readonly":
      return ["--mode", "plan"];
    case "workspace_write":
      return ["--mode", "accept-edits"];
    case "full":
      return ["--dangerously-skip-permissions"];
    case "inherit_native":
      return [];
  }
}

async function detectVersion(): Promise<string | null> {
  try {
    const r = await runCapture(AGY_BIN(), ["--version"], { timeoutMs: 10_000 });
    return r.stdout.trim() || `${AGY_BIN()} (version unknown)`;
  } catch {
    return null;
  }
}

/**
 * Manifest model truth (INV-104): the vendor's own list, captured live from
 * `agy models` on the pinned version (evidence: PLAN §1.2 F9 and the sprint
 * evidence dir; the vendor emits TSV, not JSON, in 1.1.13). Slugs
 * carry the reasoning effort (`-high`/`-medium`/`-low`) exactly like Cursor's
 * inventory, so the effort ladder is deliberately empty and an effort hint is
 * disclosed as ignored rather than mapped (Л-21). No live `models()`:
 * `agy models --output-format json` is rejected by 1.1.13 (upstream #777) and
 * the unauthenticated plain listing fails — an empty live list would refuse
 * every explicit model (PLAN §2.6).
 */
const AGY_KNOWN_MODELS = [
  "gemini-3.8-flash-high",
  "gemini-3.8-flash-medium",
  "gemini-3.8-flash-low",
  "gemini-3.7-flash-high",
  "gemini-3.7-flash-medium",
  "gemini-3.7-flash-low",
  "gemini-3.6-flash-high",
  "gemini-3.6-flash-medium",
  "gemini-3.6-flash-low",
  "gemini-3.5-flash-high",
  "gemini-3.5-flash-medium",
  "gemini-3.5-flash-low",
  "gemini-3.1-pro-high",
  "gemini-3.1-pro-low",
  "claude-sonnet-4-6",
  "claude-opus-4-6-thinking",
  "gpt-oss-120b-medium",
] as const;

/**
 * The vendor's two quota GROUPS map onto disjoint halves of the same
 * inventory: "Gemini Models" and "Claude and GPT models" (PLAN §1.2 F8). The
 * split is DERIVED from the one model list so a slug the vendor adds cannot
 * land in neither half and silently escape window scoping (INV-138).
 */
export const AGY_GEMINI_MODELS = AGY_KNOWN_MODELS.filter((m) => m.startsWith("gemini-"));
export const AGY_THIRD_PARTY_MODELS = AGY_KNOWN_MODELS.filter((m) => !m.startsWith("gemini-"));

/** One manifest-owned declaration of the managed login's stdin contract. */
export const AGY_MANAGED_LOGIN = { stdin: "terminal" } as const;

/**
 * Static auth/profile policy. Windows Credential Manager is scoped to the OS
 * user, not the profile HOME, so only one enabled binding is honest there.
 * Darwin keeps both the vendor file fallback and its private profile-local
 * keychain; Linux retains the legacy profile-scoped file route.
 */
export const AGY_CAPABILITY_PROFILE: HarnessCapabilityProfile =
  HarnessCapabilityProfileSchema.parse({
    auth: {
      supported_sources: ["native_session"],
      preferred_source: "native_session",
      credential_transports: [
        {
          source: "native_session",
          kind: "config_file",
          relocatable_by: ["HOME"],
          platforms: ["linux"],
        },
        {
          source: "native_session",
          kind: "config_file",
          relocatable_by: ["HOME"],
          platforms: ["darwin"],
        },
        {
          source: "native_session",
          kind: "os_keychain",
          relocatable_by: ["HOME"],
          platforms: ["darwin"],
        },
        {
          source: "native_session",
          kind: "os_keychain",
          relocatable_by: [],
          platforms: ["win32"],
        },
      ],
      credential_profile_policies: [
        {
          source: "native_session",
          platforms: ["win32"],
          identity_scope: "os_user",
          max_enabled_profiles: 1,
          cleanup_owner: "vendor",
        },
      ],
      managed_login: AGY_MANAGED_LOGIN,
    },
    // workspace_write rides the vendor's `--mode accept-edits` permission
    // policy — the same class as claude/cursor, not an unconfined "none".
    access_control: { readonly_mechanism: "permission_deny", write_mechanism: "tool_policy" },
    isolation: {
      supported_containment: ["env_or_file_injection", "private_per_profile_keychain"],
    },
    attachment_inputs: [],
  });

/** Platform disclosure derived from the same transport and effective-policy
 * facts used by admission. Darwin is the one live-proven profile-isolation
 * lane; other lanes stay explicit rather than maintaining parallel truth. */
export function agyPlatformIsolationDetail(
  platform: NodeJS.Platform = process.platform,
): string | null {
  const host = harnessPlatform(platform);
  if (!host) return `Antigravity credential behavior is undeclared on ${platform}`;
  const transports = credentialTransportsForPlatform(AGY_CAPABILITY_PROFILE.auth, host);
  const policy = credentialProfilePolicyForPlatform(
    AGY_CAPABILITY_PROFILE.auth,
    "native_session",
    host,
  );
  if (host === "darwin") return null;
  const kinds =
    transports.map((transport) => transport.kind).join(" + ") || "no declared transport";
  if (policy.identity_scope === "os_user") {
    return `Antigravity uses ${kinds} credentials scoped to the current OS user; the named HOME scopes vendor state but is not an independent identity (maximum ${policy.max_enabled_profiles ?? "unbounded"} enabled binding)`;
  }
  return `named-account isolation is unverified on ${host}: the declared ${kinds} transport has profile-scoped policy but no live multi-account proof on this platform`;
}

const AGY_ENABLED_INTENTS = [
  "explain",
  "plan",
  "spec",
  "implement",
  "repair",
  "create_from_scratch",
  "review",
  "verify",
  "synthesize",
  "audit",
] as const;

export interface AgyAdapterOptions {
  /** Test seam; production prepares the declared private Darwin keychain. */
  prepareProfileKeychain?: (home: string, platform?: NodeJS.Platform) => void;
}

export function createAgyAdapter(options: AgyAdapterOptions = {}): HarnessAdapter {
  const prepareProfileKeychain =
    options.prepareProfileKeychain ??
    ((home: string, platform = process.platform): void => {
      if (!needsPrivatePerProfileKeychain(AGY_CAPABILITY_PROFILE, platform)) return;
      prepareAgyProfileKeychain(home, { platform });
    });
  return {
    id: "agy",
    capabilityProfile: AGY_CAPABILITY_PROFILE,

    async discover(): Promise<HarnessManifest> {
      const version = await detectVersion();
      if (version === null) {
        throw new HarnessUnavailableError(
          "agy not found on PATH (install Antigravity CLI or set CLAUDEXOR_AGY_BIN)",
        );
      }
      return HarnessManifestSchema.parse({
        id: "agy",
        display_name: "Antigravity",
        kind: "local_cli",
        version,
        adapter_version: CLAUDEXOR_VERSION,
        provider_family: "google",
        capabilities: {
          plan: true,
          implement: true,
          create_from_scratch: true,
          review: true,
          verify: true,
          synthesize: true,
          read_files: true,
          // No MCP flag path exists (config is file-only), so no browser
          // injector is wired — honest false (INV-066).
          browser_tool: false,
          // Built-in web tools with no enforceable off switch (cursor parity).
          web_policy: "uncontrolled",
          // D-16 default recommendation (В-10): the fenced-block tier costs
          // zero extra vendor turns; the schema-constrained tier is proven to
          // force a SECOND turn per run (PLAN §1.2e) and stays off until the
          // owner opts in.
          work_report_transport: "validated",
          // Effort rides the model slug (`-high`), not a flag (Л-21).
          effort_levels: [],
          known_models: [...AGY_KNOWN_MODELS],
          known_models_verified_against: AGY_VENDOR_CLI_VERSION,
        },
        capability_profile: AGY_CAPABILITY_PROFILE,
        auth_modes: ["local_session"],
        access_profiles_supported: ["readonly", "workspace_write", "full", "inherit_native"],
      });
    },

    async doctor(spec: DoctorSpec): Promise<ConformanceReport> {
      const version = await detectVersion();
      const installedSemver =
        version === null ? null : (/\d+\.\d+\.\d+/.exec(version)?.[0] ?? null);
      const versionDrift =
        version !== null && installedSemver !== AGY_VENDOR_CLI_VERSION
          ? `installed agy "${version}" differs from the verified ${AGY_VENDOR_CLI_VERSION}; the platform credential transport and profile policy are re-proven per version (R-2')`
          : null;
      // Л-24 + INV-067: Darwin's profile-local keychain plus vendor fallback
      // preserves the proven profile identity route. Linux retains the
      // config-file transport without a live multi-account proof. Windows has
      // a different effective policy altogether: the vendor credential is
      // OS-user-scoped and HOME scopes state only.
      const platformProof = agyPlatformIsolationDetail();
      const requestedSource = spec.authSource;
      if (requestedSource !== undefined && requestedSource !== "native_session") {
        return ConformanceReportSchema.parse({
          harness_id: "agy",
          status: "unavailable",
          checks: [
            version === null
              ? { id: "installed", status: "fail", detail: "agy not found" }
              : { id: "installed", status: "pass", detail: redactSecrets(version) },
            {
              id: "auth_source",
              status: "fail",
              detail: `agy does not support ${requestedSource}`,
            },
          ],
          enabled_intents: [],
          disabled_intents: AGY_ENABLED_INTENTS,
          reasons: [`agy does not support auth source ${requestedSource}`],
          auth_sources: [
            {
              source: requestedSource,
              availability: "unavailable",
              verification: "not_run",
              detail: `agy does not support ${requestedSource}`,
            },
          ],
        });
      }
      if (version === null) {
        return ConformanceReportSchema.parse({
          harness_id: "agy",
          status: "unavailable",
          checks: [{ id: "installed", status: "fail", detail: "agy not found" }],
          enabled_intents: [],
          disabled_intents: AGY_ENABLED_INTENTS,
          reasons: ["agy not found (install Antigravity CLI or set CLAUDEXOR_AGY_BIN)"],
          auth_sources: [
            {
              source: "native_session",
              availability: "unknown",
              verification: "not_run",
              detail: "agy binary not installed",
            },
          ],
        });
      }
      // Owner decision Л-4: agy has NO engine-default credential store — every
      // account is a named profile. The harness-level doctor therefore reports
      // the default subject honestly unavailable with the remedy; PINNED
      // routing is admitted by the per-profile probe (INV-135 round-15 #1),
      // exactly like a logged-out cursor default with valid named profiles.
      return ConformanceReportSchema.parse({
        harness_id: "agy",
        status: "unavailable",
        checks: [
          { id: "installed", status: "pass", detail: redactSecrets(version) },
          {
            id: "default_credential",
            status: "fail",
            detail: "agy has no engine-default credential by design; accounts are named profiles",
          },
          ...(versionDrift
            ? [{ id: "version_pin", status: "fail" as const, detail: versionDrift }]
            : [{ id: "version_pin", status: "pass" as const, detail: AGY_VENDOR_CLI_VERSION }]),
          ...(platformProof
            ? [{ id: "platform_isolation", status: "skip" as const, detail: platformProof }]
            : []),
        ],
        enabled_intents: [],
        disabled_intents: AGY_ENABLED_INTENTS,
        reasons: [
          "agy routes only through named accounts: add one (`claudexor profiles add agy <id>` + `claudexor profiles login agy <id>`) and pin it (--profile)",
          ...(versionDrift ? [versionDrift] : []),
          ...(platformProof ? [platformProof] : []),
        ],
        auth_sources: [
          {
            source: "native_session",
            availability: "unavailable",
            verification: "not_run",
            detail: "no default store by design (accounts are named profiles)",
          },
        ],
      });
    },

    run(spec: HarnessRunSpec): AsyncIterable<HarnessEvent> {
      return runAgy(spec, prepareProfileKeychain);
    },

    review(spec: HarnessRunSpec): AsyncIterable<HarnessEvent> {
      return runAgy(spec, prepareProfileKeychain);
    },

    // INV-135: pinned routing is admitted by THIS probe (there is no default
    // store for the harness doctor to credit).
    async probeCredentialProfile(profile, abortSignal) {
      // The signal must reach the live probe: dropping it left an aborted
      // doctor sweep waiting out the probe's own 30s timeout.
      return probeAgyCredentialProfile(
        profile,
        {
          runModelProbe: defaultAgyModelProbe,
          prepareProfileKeychain: (home) => prepareProfileKeychain(home),
        },
        abortSignal,
      );
    },
  };
}

async function* runAgy(
  spec: HarnessRunSpec,
  prepareProfileKeychain: (home: string, platform?: NodeJS.Platform) => void,
): AsyncIterable<HarnessEvent> {
  const profile = spec.credential_profile;
  // Л-4: no engine-default credential — an unpinned agy run has nothing to
  // route. Typed stream refusal (error then completed), the one refusal
  // mechanism every adapter's profile gate uses.
  if (!profile) {
    yield {
      type: "error",
      session_id: spec.session_id,
      ts: nowIso(),
      error:
        "agy has no engine-default credential; pin a named account (--profile, or `claudexor profiles add agy <id>`)",
    };
    yield { type: "completed", session_id: spec.session_id, ts: nowIso() };
    return;
  }
  const route = resolveAgyProfileRoute(profile, spec.env);
  if ("refusal" in route) {
    yield { type: "error", session_id: spec.session_id, ts: nowIso(), error: route.refusal };
    yield { type: "completed", session_id: spec.session_id, ts: nowIso() };
    return;
  }

  // Path and identity failures are unsafe and stop before the vendor child.
  // A recoverable security-tool miss keeps agy's own file fallback available;
  // a custom test seam may model that same operational degradation.
  try {
    prepareProfileKeychain(route.home);
  } catch (error) {
    if (isAgyProfileKeychainUnsafe(error)) {
      yield {
        type: "error",
        session_id: spec.session_id,
        ts: nowIso(),
        error: redactSecrets(error instanceof Error ? error.message : String(error)).slice(0, 300),
      };
      yield { type: "completed", session_id: spec.session_id, ts: nowIso() };
      return;
    }
    // The vendor probe/run remains the final transport authority.
  }

  const args = ["-p", promptWithInstructions(spec), "--output-format", "stream-json"];
  // Л-18: without --add-dir agy resolves relative paths against its own app
  // data dir instead of the workspace (live-proven §1.2d).
  args.push("--add-dir", spec.cwd);
  args.push(...accessArgs(spec.access));
  if (spec.model_hint) args.push("--model", spec.model_hint);
  // INV-137: the vendor conversation id is the resumable native session.
  if (spec.resume_session_id) args.push("--conversation", spec.resume_session_id);

  yield* runCliHarness({
    bin: AGY_BIN(),
    args,
    spec,
    env: route.env,
    label: "agy",
    redact: redactSecrets,
    parseEvent: (obj, sessionId) => {
      const out = parseAgyEvent(obj, sessionId);
      if (out) {
        for (const ev of out) {
          ev.credential_route = "vendor_native";
          ev.credential_source = "native_session";
          ev.credential_profile_id = profile.profile_id;
        }
      }
      return out;
    },
  });
}
