// Application-level error type and JSON output helpers (sc-padding, self-contained).
export class AppError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export function fail(code: string, message: string): never {
  throw new AppError(code, message);
}

export function emitSuccess(obj: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify({ ok: true, ...obj }));
  process.exit(0);
}

export function emitError(err: AppError): void {
  process.stdout.write(JSON.stringify({ ok: false, error: { code: err.code, message: err.message } }));
  process.exit(1);
}
