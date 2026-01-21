import { AuthLogLevel } from "../types";

export function sessionLog(level: AuthLogLevel, message: string) {
  const prefix = "SESSION-LIB";

  switch (level) {
    case "info":
      console.info(`${prefix} ℹ️  ${message}`);
      break;
    case "warn":
      console.warn(`${prefix} ⚠️  ${message}`);
      break;
    case "error":
      console.error(`${prefix} ❌  ${message}`);
      break;
  }
}
