import { FastifyPluginAsync, FastifyRequest, FastifyReply } from "fastify";
import {
  BridgeProcessor,
  SessionWebContext,
  CookieOptions,
  buildValidateFn,
} from "./bridge";
import { ISessionService } from "../interfaces";
import { SessionLibraryConfig, SessionRecord } from "../types";

declare module "fastify" {
  interface FastifyRequest {
    cookies: Record<string, string | undefined>;
    session: SessionRecord | null;
  }
  interface FastifyReply {
    setCookie(
      name: string,
      value: string,
      opts?: {
        httpOnly?: boolean;
        secure?: boolean;
        sameSite?: "lax" | "strict" | "none";
        path?: string;
        domain?: string;
        maxAge?: number;
      },
    ): this;
    clearCookie(
      name: string,
      opts?: {
        path?: string;
        domain?: string;
        httpOnly?: boolean;
        secure?: boolean;
        sameSite?: "lax" | "strict" | "none";
      },
    ): this;
  }
}

/**
 * High-performance context implementation for Fastify.
 * Shared methods on prototype eliminate closure creation overhead.
 */
class FastifySessionContext implements SessionWebContext {
  private _clientInfo?: { ipAddress: string; userAgent?: string };

  constructor(
    private readonly request: FastifyRequest,
    private readonly reply: FastifyReply,
  ) {}

  getMethod(): string {
    return this.request.method;
  }

  getCookie(name: string): string | undefined {
    return this.request.cookies?.[name];
  }

  getHeader(name: string): string | undefined {
    const v = this.request.headers[name.toLowerCase()];
    return Array.isArray(v) ? v[0] : v;
  }

  setHeader(name: string, value: string): void {
    this.reply.header(name, value);
  }

  setCookie(name: string, value: string, opts: CookieOptions): void {
    this.reply.setCookie(name, value, {
      httpOnly: opts.httpOnly,
      secure: opts.secure,
      sameSite: opts.sameSite,
      path: opts.path,
      domain: opts.domain,
      maxAge: opts.maxAgeSeconds,
    });
  }

  clearCookie(name: string, opts: CookieOptions): void {
    this.reply.clearCookie(name, {
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
        ipAddress: this.request.ip,
        userAgent: this.request.headers["user-agent"] as string | undefined,
      };
    }
    return this._clientInfo;
  }

  setSession(session: SessionRecord): void {
    this.request.session = session;
  }

  getSession(): SessionRecord | undefined {
    return this.request.session || undefined;
  }
}

export const fastifySessionPlugin: FastifyPluginAsync<{
  service: ISessionService;
  config: SessionLibraryConfig;
}> = async (fastify, { service, config }) => {
  const processor = new BridgeProcessor(config);
  const validateFn = buildValidateFn(service);

  fastify.decorateRequest("session", null);

  fastify.addHook(
    "onRequest",
    async (request: FastifyRequest, reply: FastifyReply) => {
      await processor.handle(
        new FastifySessionContext(request, reply),
        validateFn,
      );
    },
  );
};

export const fastifyRequireSession = (
  options: { roles?: string[]; scopes?: string[] } = {},
) => {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const { session } = request;

    if (!session) {
      await reply
        .status(401)
        .send({ error: "Authentication required", code: "UNAUTHENTICATED" });
      return;
    }

    if (
      options.roles?.length &&
      !options.roles.some((r) => session.roles.includes(r))
    ) {
      await reply
        .status(403)
        .send({ error: "Insufficient permissions (roles)", code: "FORBIDDEN" });
      return;
    }

    if (
      options.scopes?.length &&
      !options.scopes.every((s) => session.scopes.includes(s))
    ) {
      await reply.status(403).send({
        error: "Insufficient permissions (scopes)",
        code: "FORBIDDEN",
      });
      return;
    }
  };
};
