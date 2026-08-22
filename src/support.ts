function hasWebAuthn(): boolean {
  return typeof navigator !== "undefined" &&
    !!navigator.credentials &&
    typeof navigator.credentials.get === "function" &&
    typeof PublicKeyCredential !== "undefined";
}

export async function canEnrollPlatformPasskey(): Promise<boolean> {
  if (!hasWebAuthn() || typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function") {
    return false;
  }
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

export async function canAttemptPasskeyUnlock(): Promise<boolean> {
  return hasWebAuthn();
}
