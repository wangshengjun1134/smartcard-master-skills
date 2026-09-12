// Minimal self-contained error type for sc-bitfield.
export class SkillError extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message ?? code);
    this.code = code;
  }
}

export function fail(code: string, message?: string): never {
  throw new SkillError(code, message);
}
