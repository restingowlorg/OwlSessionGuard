/* eslint-disable @typescript-eslint/no-namespace */
import { Request, Response, NextFunction } from "express";
import {
  BridgeProcessor,
  SessionWebContext,
  CookieOptions,
  buildValidateFn,
} from "./bridge";
import { ISessionService } from "../interfaces";
import { SessionLibraryConfig, SessionRecord } from "../types";

declare global {
  namespace Express {
    interface Request {
      session?: SessionRecord;
    }
  }
}

/**
 * High-performance context implementation for Express.
 * Shared methods on prototype eliminate closure creation overhead per request.
 */
class ExpressSessionContext implements SessionWebContext {
  private _clientInfo?: { ipAddress: string; userAgent?: string };

  constructor(
    private readonly req: Request,
    private readonly res: Response,
    private readonly shouldSignSessionCookie: boolean,
    private readonly deviceCookieName?: string,
  ) {}

  getMethod(): string {
    return this.req.method;
  }

  getCookie(name: string): string | undefined {
    // Priority: Signed cookies (trusted). Fallback: Unsigned cookies (for CSRF, etc).
    return this.req.signedCookies?.[name] ?? this.req.cookies?.[name];
  }

  getHeader(name: string): string | undefined {
    return this.req.get(name);
  }

  setHeader(name: string, value: string): void {
    this.res.setHeader(name, value);
  }

  setCookie(name: string, value: string, opts: CookieOptions): void {
    this.res.cookie(name, value, {
      httpOnly: opts.httpOnly,
      secure: opts.secure,
      sameSite: opts.sameSite,
      path: opts.path,
      domain: opts.domain,
      maxAge: opts.maxAgeSeconds ? opts.maxAgeSeconds * 1000 : undefined,
      signed: this.shouldSignSessionCookie,
    });
  }

  clearCookie(name: string, opts: CookieOptions): void {
    this.res.clearCookie(name, {
      path: opts.path,
      domain: opts.domain,
      httpOnly: opts.httpOnly,
      secure: opts.secure,
      sameSite: opts.sameSite,
    });
  }

  getClientInfo() {
    if (!this._clientInfo) {
      this._clientInfo = {
        ipAddress: this.req.ip ?? this.req.socket?.remoteAddress ?? "0.0.0.0",
        userAgent: this.req.get("user-agent"),
      };
    }
    return this._clientInfo;
  }

  setSession(session: SessionRecord): void {
    this.req.session = session;
  }

  getSession(): SessionRecord | undefined {
    return this.req.session;
  }

  getDeviceId(): string | undefined {
    if (!this.deviceCookieName) return undefined;
    return (
      this.req.signedCookies?.[this.deviceCookieName] ??
      this.req.cookies?.[this.deviceCookieName]
    );
  }
}

export const createExpressMiddleware = (
  service: ISessionService,
  config: SessionLibraryConfig,
) => {
  const processor = new BridgeProcessor(config);
  const validateFn = buildValidateFn(service);

  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      const shouldSignSessionCookie = config.transport.cookie?.signed ?? false;
      await processor.handle(
        new ExpressSessionContext(
          req,
          res,
          shouldSignSessionCookie,
          processor.deviceCookieName,
        ),
        validateFn,
      );
      next();
    } catch (error) {
      next(error);
    }
  };
};

export const requireSession = (
  options: { roles?: string[]; scopes?: string[] } = {},
) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const { session } = req;

    if (!session) {
      res
        .status(401)
        .json({ error: "Authentication required", code: "UNAUTHENTICATED" });
      return;
    }

    if (
      options.roles?.length &&
      !options.roles.some((r) => session.roles.includes(r))
    ) {
      res
        .status(403)
        .json({ error: "Insufficient permissions (roles)", code: "FORBIDDEN" });
      return;
    }

    if (
      options.scopes?.length &&
      !options.scopes.every((s) => session.scopes.includes(s))
    ) {
      res.status(403).json({
        error: "Insufficient permissions (scopes)",
        code: "FORBIDDEN",
      });
      return;
    }

    next();
  };
};
