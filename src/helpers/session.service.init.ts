import { SessionOptions } from "../types";
import { SessionService } from "../services/session.service";
import { SessionResult } from "../interfaces"
import { sessionLog } from "../utils/logger";

/**
 * Initialize session service
 */
export async function initSessionServices(db: any, options: SessionOptions) {
  const sessionService = new SessionService(
    db.sessionRepo,
    options.maxSessionsPerUser,
  );

  sessionLog("info", "Successfully initialized session service");
  sessionLog(
    "info",
    "Provided functions: createSession, validateSession, rotateSession, revokeSession",
  );

  return {
    create: (userId: string, ttl?: number): Promise<SessionResult> =>
      sessionService.create(
        userId,
        ttl ?? options.sessionTtlSeconds ?? 60 * 60 * 24 * 7,
      ),

    validate: (
      token: string,
      idleTtl?: number,
    ): Promise<SessionResult> => sessionService.validate(token, idleTtl),

    rotate: (token: string): Promise<SessionResult> =>
      sessionService.rotate(token),

    revoke: (token: string): Promise<SessionResult> =>
      sessionService.destroy(token),
  };
}
