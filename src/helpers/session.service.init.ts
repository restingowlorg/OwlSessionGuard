import { SessionOptions } from "../types";
import { SessionService } from "../services/session.service";
import { SessionResult } from "../types";

/**
 * Initialize session service
 */
export async function initSessionServices(db: any, options: SessionOptions) {
  const sessionService = new SessionService(db.sessionRepo, options.maxSessionsPerUser);

  return {
    createSession: (userId: string, ttl?: number): Promise<SessionResult> =>
      sessionService.create(userId, ttl ?? options.sessionTtlSeconds ?? 60 * 60 * 24 * 7),

    validateSession: (token: string, idleTtl?: number): Promise<SessionResult> =>
      sessionService.validate(token, idleTtl),

    rotateSession: (token: string): Promise<SessionResult> =>
      sessionService.rotate(token),

    revokeSession: (token: string): Promise<void> =>
      sessionService.destroy(token).then(() => undefined), // convert SessionResult → void
  };
}
