import { SessionOptions } from "./types";
import { initDatabase } from "./helpers/database.init";
import { ISessionManager } from "./interfaces";
import { initSessionServices } from "./helpers/session.service.init";

/**
 * SessionManager — OWASP V7 compliant session management
 */
export class SessionManager implements ISessionManager {
  public create!: ISessionManager["create"];
  public validate!: ISessionManager["validate"];
  public rotate!: ISessionManager["rotate"];
  public revoke!: ISessionManager["revoke"];

  private constructor() {}

  public static async init(options: SessionOptions): Promise<SessionManager> {
    const manager = new SessionManager();

    const db = await initDatabase(options);
    const services = await initSessionServices(db, options);

    Object.assign(manager, services);

    return manager;
  }
}