import {
  SessionRecord,
  SessionLibraryConfig,
  SessionStatus,
  ValidateFunction,
  ValidateResult,
} from "../types";
import { buildValidateFn } from "./validate-fn";

export { buildValidateFn };

/** Internal symbol to prevent session spoofing via other middlewares. */
const OSSEC_SESSION_MARKER = Symbol("ossec:session:trusted");

export interface CookieOptions {
  httpOnly: boolean;
  secure: boolean;
  sameSite: "lax" | "strict" | "none";
  path?: string;
  domain?: string;
  maxAgeSeconds?: number;
}

export interface SessionWebContext {
  getMethod(): string;
  getCookie(name: string): string | undefined;
  getHeader(name: string): string | undefined;
  setHeader(name: string, value: string): void;
  setCookie(name: string, value: string, options: CookieOptions): void;
  clearCookie(name: string, options: CookieOptions): void;
  getClientInfo(): { ipAddress: string; userAgent?: string };
  setSession(
    session: SessionRecord & { [OSSEC_SESSION_MARKER]?: boolean },
  ): void;
  getSession():
    | (SessionRecord & { [OSSEC_SESSION_MARKER]?: boolean })
    | undefined;
  getDeviceId?(): string | undefined;
}

export class BridgeProcessor {
  private readonly cookieName: string;
  private readonly transportMode: "cookie" | "header" | "hybrid";
  private readonly headerName: string;
  private readonly headerScheme?: string;
  private readonly responseHeaderName: string;
  private readonly cookieOptions: CookieOptions;
  private readonly csrfConfig: {
    enabled: boolean;
    cookieName: string;
    headerName: string;
  };
  // WHY: Device cookie config is separate from session cookie because deviceId
  // is a persistent identifier that outlives individual session tokens.
  private readonly deviceConfig: {
    enabled: boolean;
    cookieName: string;
    cookieOptions: CookieOptions;
  };

  constructor(config: SessionLibraryConfig) {
    const { transport, security } = config;
    this.transportMode = transport.mode;
    this.cookieName = transport.cookie?.name || "session_id";
    this.headerName = (transport.header?.name || "Authorization").toLowerCase();
    this.headerScheme = transport.header?.scheme
      ? transport.header.scheme.toLowerCase() + " "
      : undefined;
    this.responseHeaderName =
      transport.header?.responseHeader || "X-Session-Token";
    this.csrfConfig = {
      ...security.csrf,
      cookieName: security.csrf.cookieName || "x-csrf-token",
      headerName: (security.csrf.headerName || "x-csrf-token").toLowerCase(),
    };

    const c = transport.cookie;
    this.cookieOptions = {
      httpOnly: c?.httpOnly ?? true,
      secure: c?.secure ?? true,
      sameSite: c?.sameSite ?? "lax",
      path: c?.path ?? "/",
      domain: c?.domain,
      maxAgeSeconds: c?.maxAgeSeconds,
    };

    if (this.cookieOptions.sameSite === "none" && !this.cookieOptions.secure) {
      throw new Error("[OSSEC] SameSite=None requires Secure=true.");
    }

    // WHY: Device cookie inherits secure defaults from session cookie config
    // but has its own name and httpOnly setting. The device ID is an opaque
    // identifier — it must not be readable by frontend JS (httpOnly: true).
    const dc = config.device;
    this.deviceConfig = {
      enabled: dc?.enabled ?? false,
      cookieName: dc?.cookie?.name || "device_id",
      cookieOptions: {
        httpOnly: dc?.cookie?.httpOnly ?? true,
        secure: dc?.cookie?.secure ?? this.cookieOptions.secure,
        sameSite: dc?.cookie?.sameSite ?? this.cookieOptions.sameSite,
        path: dc?.cookie?.path ?? this.cookieOptions.path,
        domain: dc?.cookie?.domain ?? this.cookieOptions.domain,
        maxAgeSeconds: dc?.cookie?.maxAgeSeconds,
      },
    };

    // WHY: Enforce SameSite=None requires Secure=true for device cookie,
    // same constraint as session cookie. Prevents silent browser rejection.
    if (
      this.deviceConfig.enabled &&
      this.deviceConfig.cookieOptions.sameSite === "none" &&
      !this.deviceConfig.cookieOptions.secure
    ) {
      throw new Error(
        "[OSSEC] Device cookie: SameSite=None requires Secure=true.",
      );
    }
  }

  public get deviceCookieName(): string | undefined {
    return this.deviceConfig.enabled ? this.deviceConfig.cookieName : undefined;
  }

  public async handle(
    context: SessionWebContext,
    validateFn: ValidateFunction,
  ): Promise<boolean> {
    const existing = context.getSession();
    if (existing && existing[OSSEC_SESSION_MARKER]) return true;

    const extraction = this.extractToken(context);
    if (!extraction) return false;

    let csrfToken: string | undefined;
    if (this.csrfConfig.enabled) {
      csrfToken = context.getHeader(this.csrfConfig.headerName);
    }

    const clientInfo = {
      ...context.getClientInfo(),
      method: context.getMethod(),
      csrfToken,
    };

    let result: ValidateResult;
    try {
      result = await validateFn(extraction.token, clientInfo);
    } catch {
      // WHY: If the consumer's validateFn throws synchronously or rejects,
      // treat it as a validation failure — never crash the request pipeline.
      return false;
    }

    if (!result.success) {
      return this.handleFailure(context, extraction.source, result);
    }

    return this.handleSuccess(context, result);
  }

  private handleFailure(
    context: SessionWebContext,
    source: "header" | "cookie",
    result: ValidateResult,
  ): boolean {
    // WHY: Cookie clear failures are non-critical — the session is already
    // revoked server-side. The cookie in the browser is useless regardless.
    if (source === "cookie" && result.error && result.error.httpCode < 500) {
      try {
        context.clearCookie(this.cookieName, this.cookieOptions);
      } catch {
        // Non-critical: session revoked server-side
      }
    }

    // WHY: On validation failure, clear the CSRF cookie if the service signals it.
    // This prevents stale CSRF tokens from persisting after session revocation.
    if (result.clearCsrfToken) {
      this.clearCsrfCookie(context);
    }

    return false;
  }

  private handleSuccess(
    context: SessionWebContext,
    result: ValidateResult,
  ): boolean {
    if (!result.data) {
      // WHY: success:true with no data is an acknowledgment (e.g. revocation).
      // The request should not proceed as authenticated — no session to attach.
      return false;
    }

    const record = result.data as SessionRecord & {
      [OSSEC_SESSION_MARKER]?: boolean;
    };

    // WHY: Revoked sessions must not proceed as authenticated.
    // The service returns success:true for revocation acknowledgments,
    // but the bridge must treat them as non-authenticated.
    if (record.status === SessionStatus.REVOKED) {
      this.applyOperationResult(context, result);
      return false;
    }

    record[OSSEC_SESSION_MARKER] = true;
    context.setSession(record);

    if (result.newToken) {
      this.applyTokenRotation(context, result.newToken);
    }

    this.applyOperationResult(context, result);

    return true;
  }

  // WHY: Session cookie write is critical — if it fails, the user cannot
  // authenticate. The error must propagate so the consumer can return a 500.
  private applyTokenRotation(
    context: SessionWebContext,
    newToken: string,
  ): void {
    if (this.transportMode !== "header") {
      context.setCookie(this.cookieName, newToken, this.cookieOptions);
    }
    if (this.transportMode !== "cookie") {
      context.setHeader(this.responseHeaderName, newToken);
    }
  }

  // WHY: Centralizes CSRF and device cookie propagation from service results.
  // Eliminates duplication between success and failure paths.
  private applyOperationResult(
    context: SessionWebContext,
    result: ValidateResult,
  ): void {
    if (result.newCsrfToken) {
      this.writeCsrfCookie(context, result.newCsrfToken);
    }
    if (result.clearCsrfToken) {
      this.clearCsrfCookie(context);
    }
  }

  private extractToken(
    context: SessionWebContext,
  ): { token: string; source: "header" | "cookie" } | undefined {
    if (this.transportMode !== "cookie") {
      const val = context.getHeader(this.headerName);
      if (val) {
        if (this.headerScheme) {
          const schemeLen = this.headerScheme.length;
          if (
            val.length > schemeLen &&
            val.slice(0, schemeLen).toLowerCase() === this.headerScheme
          ) {
            const token = val.slice(schemeLen).trim();
            if (token) return { token, source: "header" };
          }
        } else {
          const token = val.trim();
          if (token) return { token, source: "header" };
        }
      }
    }

    if (this.transportMode !== "header") {
      const token = context.getCookie(this.cookieName);
      if (token) {
        return { token: token.trim(), source: "cookie" };
      }
    }

    return undefined;
  }

  public writeSessionCookie(context: SessionWebContext, token: string) {
    if (this.transportMode !== "header") {
      context.setCookie(this.cookieName, token, this.cookieOptions);
    }
  }

  public clearSessionCookie(context: SessionWebContext) {
    if (this.transportMode !== "header") {
      try {
        context.clearCookie(this.cookieName, this.cookieOptions);
      } catch {
        // Non-critical: session revoked server-side
      }
    }
  }

  // WHY: CSRF cookie write is critical — without it, CSRF protection is broken.
  // The error must propagate so the consumer can return a 500.
  public writeCsrfCookie(context: SessionWebContext, csrfToken: string) {
    if (this.csrfConfig.enabled) {
      context.setCookie(this.csrfConfig.cookieName, csrfToken, {
        ...this.cookieOptions,
        httpOnly: false, // CSRF token MUST be readable by frontend JS
      });
    }
  }

  public clearCsrfCookie(context: SessionWebContext) {
    if (this.csrfConfig.enabled) {
      try {
        context.clearCookie(this.csrfConfig.cookieName, {
          ...this.cookieOptions,
          httpOnly: false,
        });
      } catch {
        // Non-critical: session revoked server-side
      }
    }
  }

  // WHY: Writes a persistent device identifier cookie. This is the standard
  // entry point for consumers — keeps cookie name and options centralized
  // in the bridge so framework middlewares don't duplicate config logic.
  public writeDeviceIdCookie(context: SessionWebContext, deviceId: string) {
    if (!this.deviceConfig.enabled) return;

    // WHY: Reject empty or oversized deviceId at the boundary to prevent
    // silent cookie collision or denial-of-service via cookie size limits.
    // Max 512 matches DeviceContextExtractor validation.
    if (!deviceId || deviceId.length > 512) return;

    try {
      context.setCookie(
        this.deviceConfig.cookieName,
        deviceId,
        this.deviceConfig.cookieOptions,
      );
    } catch {
      // Non-critical: device tracking is nice-to-have, not essential for auth.
    }
  }

  // WHY: Clears the device identifier cookie on logout or session tree revocation.
  public clearDeviceIdCookie(context: SessionWebContext) {
    if (this.deviceConfig.enabled) {
      try {
        context.clearCookie(
          this.deviceConfig.cookieName,
          this.deviceConfig.cookieOptions,
        );
      } catch {
        // Non-critical: session revoked server-side
      }
    }
  }
}
