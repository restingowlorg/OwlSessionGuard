import {
  CanActivate,
  ExecutionContext,
  Injectable,
  createParamDecorator,
  UnauthorizedException,
  ForbiddenException,
  SetMetadata,
  NestInterceptor,
  CallHandler,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Observable } from "rxjs";
import {
  BridgeProcessor,
  SessionWebContext,
  CookieOptions,
  buildValidateFn,
} from "./bridge";
import { ISessionService } from "../interfaces";
import { SessionLibraryConfig, SessionRecord } from "../types";

/** Extended request type with protocol-safe optional properties. */
export interface SessionRequest {
  session?: SessionRecord;
  cookies?: Record<string, string>;
  signedCookies?: Record<string, string>;
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
  method?: string;
  socket?: { remoteAddress?: string };
}

/** Response interface restricted to HTTP-only operations. */
export interface SessionResponse {
  header?: (name: string, value: string) => void;
  cookie?: (name: string, value: string, options: unknown) => void;
  clearCookie?: (name: string, options: unknown) => void;
}

/**
 * High-performance context implementation for NestJS.
 * Shared methods on prototype eliminate closure creation overhead.
 */
class NestSessionContext implements SessionWebContext {
  private _clientInfo?: { ipAddress: string; userAgent?: string };

  constructor(
    private readonly req: SessionRequest,
    private readonly res: SessionResponse,
    private readonly shouldSignSessionCookie: boolean,
    private readonly deviceCookieName?: string,
  ) {}

  getMethod(): string {
    return this.req.method || "GET";
  }

  getCookie(name: string): string | undefined {
    return this.req.signedCookies?.[name] ?? this.req.cookies?.[name];
  }

  getHeader(name: string): string | undefined {
    const v = this.req.headers[name.toLowerCase()];
    return Array.isArray(v) ? v[0] : v;
  }

  setHeader(name: string, value: string): void {
    this.res.header?.(name, value);
  }

  setCookie(name: string, value: string, opts: CookieOptions): void {
    this.res.cookie?.(name, value, {
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
    this.res.clearCookie?.(name, {
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
        userAgent: this.req.headers["user-agent"] as string | undefined,
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

export const ROLES_KEY = "owlsessionguard:roles";
export const SCOPES_KEY = "owlsessionguard:scopes";
export const RequireRoles = (...roles: string[]) =>
  SetMetadata(ROLES_KEY, roles);
export const RequireScopes = (...scopes: string[]) =>
  SetMetadata(SCOPES_KEY, scopes);

@Injectable()
export class SessionGuard implements CanActivate {
  private readonly processor: BridgeProcessor;
  private readonly validateFn: ReturnType<typeof buildValidateFn>;

  constructor(
    service: ISessionService,
    private readonly config: SessionLibraryConfig,
    private readonly reflector: Reflector,
  ) {
    this.processor = new BridgeProcessor(config);
    this.validateFn = buildValidateFn(service);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (context.getType() !== "http") {
      throw new UnauthorizedException(
        "SessionGuard only supports HTTP context",
      );
    }

    const http = context.switchToHttp();
    const req = http.getRequest<SessionRequest>();
    const res = http.getResponse<SessionResponse>();

    const shouldSignSessionCookie =
      this.config.transport.cookie?.signed ?? false;

    const isValid = await this.processor.handle(
      new NestSessionContext(
        req,
        res,
        shouldSignSessionCookie,
        this.processor.deviceCookieName,
      ),
      this.validateFn,
    );

    if (!isValid || !req.session)
      throw new UnauthorizedException("Invalid or missing session");

    const { session } = req;
    const roles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (
      roles?.length &&
      !roles.some((role: string) => session.roles.includes(role))
    ) {
      throw new ForbiddenException("Insufficient roles");
    }

    const scopes = this.reflector.getAllAndOverride<string[]>(SCOPES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (
      scopes?.length &&
      !scopes.every((scope: string) => session.scopes.includes(scope))
    ) {
      throw new ForbiddenException("Insufficient scopes");
    }

    return true;
  }
}

@Injectable()
export class SessionInterceptor implements NestInterceptor {
  private readonly processor: BridgeProcessor;
  private readonly validateFn: ReturnType<typeof buildValidateFn>;

  constructor(
    private readonly service: ISessionService,
    private readonly config: SessionLibraryConfig,
  ) {
    this.processor = new BridgeProcessor(config);
    this.validateFn = buildValidateFn(service);
  }

  async intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Promise<Observable<unknown>> {
    if (context.getType() === "http") {
      const http = context.switchToHttp();
      const shouldSignSessionCookie =
        this.config.transport.cookie?.signed ?? false;
      await this.processor.handle(
        new NestSessionContext(
          http.getRequest<SessionRequest>(),
          http.getResponse<SessionResponse>(),
          shouldSignSessionCookie,
          this.processor.deviceCookieName,
        ),
        this.validateFn,
      );
    }
    return next.handle();
  }
}

export const Session = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): SessionRecord | undefined => {
    if (ctx.getType() !== "http") return undefined;
    return ctx.switchToHttp().getRequest<SessionRequest>().session;
  },
);
