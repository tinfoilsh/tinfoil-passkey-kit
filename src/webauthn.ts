import { base64UrlToBytes, bufferSourceToArrayBuffer, bytesToBase64Url } from "./codec.js";
import { invalidInput, PasskeyKeyError } from "./errors.js";
import type { PasskeyUser } from "./types.js";

const CHALLENGE_BYTES = 32;
const MAX_USER_HANDLE_BYTES = 64;
const PRF_OUTPUT_BYTES = 32;

export interface CeremonyContext {
  rpId: string;
  rpName: string;
  prfInput: Uint8Array;
  timeoutMs: number;
}

export interface InternalPrfResult {
  credentialId: string;
  prfOutput: Uint8Array;
  isPlatformAuthenticator: boolean;
}

interface PrfExtensionResults {
  prf?: {
    enabled?: boolean;
    results?: { first?: BufferSource };
  };
}

function extensionResults(credential: PublicKeyCredential): PrfExtensionResults {
  return credential.getClientExtensionResults() as PrfExtensionResults;
}

function credentialId(credential: PublicKeyCredential): string {
  const rawId = new Uint8Array(credential.rawId);
  if (rawId.length === 0) throw invalidInput("credential ID must not be empty");
  return bytesToBase64Url(rawId);
}

function resultFromCredential(credential: PublicKeyCredential): InternalPrfResult {
  const first = extensionResults(credential).prf?.results?.first;
  if (!first) {
    throw new PasskeyKeyError("unsupported", "the authenticator returned no PRF output");
  }
  const prfOutput = new Uint8Array(bufferSourceToArrayBuffer(first));
  if (prfOutput.length !== PRF_OUTPUT_BYTES) {
    throw invalidInput(`PRF output must be ${PRF_OUTPUT_BYTES} bytes`);
  }
  return {
    credentialId: credentialId(credential),
    prfOutput,
    isPlatformAuthenticator: credential.authenticatorAttachment === "platform",
  };
}

export async function createPrfCredential(
  context: CeremonyContext,
  user: PasskeyUser,
  signal: AbortSignal,
): Promise<InternalPrfResult> {
  if (!(user?.id instanceof Uint8Array) || user.id.length === 0) {
    throw invalidInput("user.id must be a non-empty Uint8Array");
  }
  if (user.id.length > MAX_USER_HANDLE_BYTES) {
    throw invalidInput(`user.id must be at most ${MAX_USER_HANDLE_BYTES} bytes`);
  }
  if (typeof user.name !== "string" || user.name.length === 0) {
    throw invalidInput("user.name must be a non-empty string");
  }
  if (user.displayName !== undefined && (typeof user.displayName !== "string" || !user.displayName)) {
    throw invalidInput("user.displayName must be a non-empty string");
  }

  const credential = (await navigator.credentials.create({
    signal,
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(CHALLENGE_BYTES)),
      rp: { id: context.rpId, name: context.rpName },
      user: {
        id: user.id.slice(),
        name: user.name,
        displayName: user.displayName ?? user.name,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "preferred",
        userVerification: "required",
      },
      timeout: context.timeoutMs,
      extensions: {
        prf: { eval: { first: context.prfInput.slice() } },
      } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new PasskeyKeyError(
      "cancelled",
      "credential creation was cancelled or no eligible credential was available",
    );
  }
  const extension = extensionResults(credential).prf;
  if (!extension?.enabled) {
    throw new PasskeyKeyError("unsupported", "the authenticator does not support PRF");
  }
  if (extension.results?.first) return resultFromCredential(credential);

  return evaluatePrfCredential(context, [credentialId(credential)], signal);
}

export async function evaluatePrfCredential(
  context: CeremonyContext,
  credentialIds: string[],
  signal: AbortSignal,
): Promise<InternalPrfResult> {
  const assertion = (await navigator.credentials.get({
    signal,
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(CHALLENGE_BYTES)),
      rpId: context.rpId,
      allowCredentials: credentialIds.map((credentialId) => ({
        type: "public-key",
        id: base64UrlToBytes(credentialId) as BufferSource,
      })),
      userVerification: "required",
      timeout: context.timeoutMs,
      extensions: {
        prf: { eval: { first: context.prfInput.slice() } },
      } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!assertion) {
    throw new PasskeyKeyError(
      "cancelled",
      "credential evaluation was cancelled or no eligible credential was available",
    );
  }
  return resultFromCredential(assertion);
}
