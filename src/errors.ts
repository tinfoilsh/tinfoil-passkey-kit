export type PasskeyKeyErrorCode =
  | "cancelledOrUnavailable"
  | "timeout"
  | "prfUnsupported"
  | "operationInProgress"
  | "invalidInput"
  | "cryptoFailure";

export class PasskeyKeyError extends Error {
  readonly code: PasskeyKeyErrorCode;
  readonly operation?: string;
  readonly cause?: unknown;

  constructor(
    code: PasskeyKeyErrorCode,
    message: string,
    options: { cause?: unknown; operation?: string } = {},
  ) {
    super(message);
    this.name = "PasskeyKeyError";
    this.code = code;
    this.operation = options.operation;
    this.cause = options.cause;
  }
}

export function invalidInput(message: string, operation?: string): PasskeyKeyError {
  return new PasskeyKeyError("invalidInput", message, { operation });
}

export function cryptoFailure(
  message: string,
  cause: unknown,
  operation?: string,
): PasskeyKeyError {
  return new PasskeyKeyError("cryptoFailure", message, { cause, operation });
}
