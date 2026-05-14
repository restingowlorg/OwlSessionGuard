import { SessionRecord, SessionLibraryConfig } from "../types";
import { ISessionService } from "../interfaces";

/** Internal symbol to prevent session spoofing via other middlewares. */
const OSSEC_SESSION_MARKER = Symbol.for("ossec:session:trusted");

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
    mode: "double-submit" | "external";
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
    this.csrfConfig = security.csrf;

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
  }

  public async handle(
    context: SessionWebContext,
    validateFn: (
      token: string,
      clientInfo: { ipAddress: string; userAgent?: string },
    ) => Promise<{
      success: boolean;
      data?: SessionRecord;
      error?: { message: string; httpCode: number };
      newToken?: string;
    }>,
  ): Promise<boolean> {
    const existing = context.getSession();
    if (existing && existing[OSSEC_SESSION_MARKER]) return true;

    const extraction = this.extractToken(context);
    if (!extraction) return false;

    // 1. Optimized CSRF: Avoid toUpperCase() allocation
    if (this.csrfConfig.enabled && this.csrfConfig.mode === "double-submit") {
      const m = context.getMethod();
      // Fast check for safe methods (idempotent)
      const isSafe =
        m === "GET" ||
        m === "HEAD" ||
        m === "OPTIONS" ||
        m === "get" ||
        m === "head" ||
        m === "options";

      if (!isSafe) {
        const csrfCookie = context.getCookie("x-csrf-token");
        const csrfHeader = context.getHeader("x-csrf-token");
        if (!csrfCookie || csrfCookie !== csrfHeader) {
          return false;
        }
      }
    }

    const result = await validateFn(extraction.token, context.getClientInfo());

    if (!result.success) {
      if (
        extraction.source === "cookie" &&
        result.error &&
        result.error.httpCode < 500
      ) {
        context.clearCookie(this.cookieName, this.cookieOptions);
      }
      return false;
    }

    if (result.data) {
      const record = result.data as SessionRecord & {
        [OSSEC_SESSION_MARKER]?: boolean;
      };
      record[OSSEC_SESSION_MARKER] = true;
      context.setSession(record);

      if (result.newToken) {
        if (this.transportMode !== "header") {
          context.setCookie(
            this.cookieName,
            result.newToken,
            this.cookieOptions,
          );
        }
        if (this.transportMode !== "cookie") {
          context.setHeader(this.responseHeaderName, result.newToken);
        }
      }
    }

    return true;
  }

  private extractToken(
    context: SessionWebContext,
  ): { token: string; source: "header" | "cookie" } | undefined {
    if (this.transportMode !== "cookie") {
      const val = context.getHeader(this.headerName);
      if (val) {
        if (this.headerScheme) {
          // Optimized: Only lowercase the prefix portion, avoid full string copy
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
      context.clearCookie(this.cookieName, this.cookieOptions);
    }
  }
}

export function buildValidateFn(service: ISessionService) {
  return async (
    token: string,
    clientInfo: { ipAddress: string; userAgent?: string },
  ) => {
    const result = await service.validateSession({
      token,
      context: {
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
      },
    });

    if (result && result.success) {
      return {
        success: true as const,
        data: result.data,
        newToken: result.newToken,
      };
    }

    return {
      success: false as const,
      error: {
        message: result.error?.message || "Invalid session",
        httpCode: result.httpCode || 401,
      },
    };
  };
}
