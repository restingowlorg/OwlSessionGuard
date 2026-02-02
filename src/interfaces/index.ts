
export interface ISessionManager {
  create(subjectId: string): Promise<SessionResult>;
  validate(token: string, idleTtlSeconds?: number): Promise<SessionResult>;
  rotate(token: string): Promise<SessionResult>;
  revoke(token: string): Promise<SessionResult>;
}

export interface SessionDB {
  sessionRepo: any;
}

export interface SessionResult<T = any> {
  success: boolean;
  data?: T;
  httpCode: number;
  message: string;
}