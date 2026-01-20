import { SessionResult } from "./types";

export interface ISessionManager {
  create(subjectId: string, ttlSeconds: number): Promise<SessionResult>;
  validate(token: string, idleTtlSeconds?: number): Promise<SessionResult>;
  rotate(token: string): Promise<SessionResult>;
  revoke(token: string): Promise<void>;
}
