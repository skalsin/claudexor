import type { PinnedVendorCliVersion } from "@claudexor/util";

/**
 * The Antigravity CLI (`agy`) version this adapter's recorded fixtures,
 * manifest `known_models` list, and file-token-fallback proof were captured
 * against. Unlike the claude/codex constants this is NOT an npm install pin —
 * agy ships as a closed Google binary with no npm artifact (the installer
 * uses the vendor's official script, cursor-style, `human_observed`). It IS
 * the verification stamp: `known_models_verified_against` reads it, fixture
 * provenance records it, and the doctor discloses drift when the installed
 * binary self-updates past it. The profile file-token fallback is re-proven
 * per bump of this constant. On Darwin a private profile keychain is prepared
 * through a neutral bootstrap/adoption step before the vendor child; the file
 * fallback remains vendor-owned recovery behavior. This Darwin exception
 * supersedes the historical file-only lock in PLAN Л-15/R-2' under
 * CONCEPT-CHANGE(INV-067, INV-135).
 */
export const AGY_VENDOR_CLI_VERSION: PinnedVendorCliVersion = "1.2.12";
