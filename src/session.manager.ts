import { SessionOptions } from "./types";
import { initDatabase } from "./helpers/database.init";
import { ISessionManager } from "./interfaces";
import { initSessionServices } from "./helpers/session.service.init";


export class SessionManager implements ISessionManager {
  public create!: ISessionManager["create"];
  public validate!: ISessionManager["validate"];
  public rotate!: ISessionManager["rotate"];
  public revoke!: ISessionManager["revoke"];

  private constructor() {}

  public static async init(options: SessionOptions): Promise<SessionManager> {
    const manager = new SessionManager();

    // Initialize database
    const db = await initDatabase(options);

    // Initialize session services with the database and options
    const services = await initSessionServices(db, options);

    // Assign the service functions to the manager instance
    Object.assign(manager, services);

    return manager;
  }
}