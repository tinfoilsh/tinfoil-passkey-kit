export type PasskeyKeyErrorCategory =
  | "unsupported"
  | "cancelled"
  | "timeout"
  | "operation_in_progress"
  | "invalid_input"
  | "operation_failed";

export class PasskeyKeyError extends Error {
  readonly category: PasskeyKeyErrorCategory;
  readonly operation?: string;
  readonly cause?: unknown;

  constructor(
    category: PasskeyKeyErrorCategory,
    message: string,
    options: { cause?: unknown; operation?: string } = {},
  ) {
    super(message);
    this.name = "PasskeyKeyError";
    this.category = category;
    this.operation = options.operation;
    this.cause = options.cause;
  }
}

export function invalidInput(message: string, operation?: string): PasskeyKeyError {
  return new PasskeyKeyError("invalid_input", message, { operation });
}

export function operationFailed(
  message: string,
  cause: unknown,
  operation?: string,
): PasskeyKeyError {
  return new PasskeyKeyError("operation_failed", message, { cause, operation });
}
