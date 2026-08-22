import type { PasskeyCapability } from "./types.js";

function hasWebAuthn(operation: "enroll" | "recover"): boolean {
  return (
    typeof navigator !== "undefined" &&
    !!navigator.credentials &&
    typeof navigator.credentials[operation === "enroll" ? "create" : "get"] ===
      "function" &&
    typeof PublicKeyCredential !== "undefined"
  );
}

async function prfCapability(): Promise<PasskeyCapability> {
  const credentialClass = PublicKeyCredential as typeof PublicKeyCredential & {
    getClientCapabilities?: () => Promise<Record<string, boolean>>;
  };
  if (typeof credentialClass.getClientCapabilities !== "function") return "unknown";
  try {
    const capabilities = await credentialClass.getClientCapabilities();
    const reported = capabilities["extension-prf"] ?? capabilities.prf;
    if (reported === true) return "supported";
    if (reported === false) return "unsupported";
  } catch {
    return "unknown";
  }
  return "unknown";
}

export async function capability(
  operation: "enroll" | "recover",
): Promise<PasskeyCapability> {
  if (!hasWebAuthn(operation)) return "unsupported";
  if (operation === "recover") return prfCapability();
  if (
    typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function"
  ) {
    return "unknown";
  }
  try {
    if (!(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())) {
      return "unsupported";
    }
  } catch {
    return "unknown";
  }
  return prfCapability();
}
