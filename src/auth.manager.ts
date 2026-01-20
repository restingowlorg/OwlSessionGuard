import { SessionOptions } from "./types";
import { DEFAULTS } from "./config/defaults";
import { initDatabase } from "./helpers/database.init";
import { ISessionManager } from "./interfaces";
import { initSessionServices } from "./helpers/session.service.init";
import { SessionResult } from "./types";

/**
 * SessionManager — OWASP V7 compliant session management
 */
export class SessionManager implements ISessionManager {
  private sessionService!: {
    createSession: (userId: string, ttl?: number) => Promise<SessionResult>;
    validateSession: (token: string, idleTtl?: number) => Promise<SessionResult>;
    rotateSession: (token: string) => Promise<SessionResult>;
    revokeSession: (token: string) => Promise<void>;
  };

  private sessionTtl!: number;

  private constructor() {}

  /**
   * Initialize the SessionManager
   */
  public static async init(options: SessionOptions): Promise<SessionManager> {
    const manager = new SessionManager();

    // ---------------- Database ----------------
    const db = await initDatabase(options);

    // Set session TTL
    manager.sessionTtl = options.sessionTtlSeconds ?? DEFAULTS.SESSION_TTL;

    // ---------------- Session Services ----------------
    manager.sessionService = await initSessionServices(db, options);

    return manager;
  }

  // ---------------- ISessionManager Implementation ----------------

  public create(subjectId: string, ttlSeconds?: number): Promise<SessionResult> {
    return this.sessionService.createSession(subjectId, ttlSeconds ?? this.sessionTtl);
  }

  public validate(token: string, idleTtlSeconds?: number): Promise<SessionResult> {
    return this.sessionService.validateSession(token, idleTtlSeconds);
  }

  public rotate(token: string): Promise<SessionResult> {
    return this.sessionService.rotateSession(token);
  }

  public revoke(token: string): Promise<void> {
    return this.sessionService.revokeSession(token);
  }
}
