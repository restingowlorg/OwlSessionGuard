import { ISessionService } from "../interfaces";
import { ValidateFunction } from "../types";

function buildDefaultValidateFn(service: ISessionService): ValidateFunction {
  return async (token, clientInfo) => {
    const result = await service.validateSession({
      token,
      csrfToken: clientInfo.csrfToken,
      context: {
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        method: clientInfo.method,
        ...(clientInfo.deviceFingerprint !== undefined
          ? { deviceFingerprint: clientInfo.deviceFingerprint }
          : {}),
      },
    });

    if (result && result.success) {
      return {
        success: true,
        data: result.data,
        newToken: result.newToken,
        newCsrfToken: result.newCsrfToken,
        clearCsrfToken: result.clearCsrfToken,
      };
    }

    return {
      success: false,
      error: {
        message: result.error?.message || "Invalid session",
        httpCode: result.httpCode || 401,
      },
      clearCsrfToken: result.clearCsrfToken,
    };
  };
}

function buildRotateValidateFn(service: ISessionService): ValidateFunction {
  return async (token, clientInfo) => {
    const result = await service.rotateSession({
      token,
      context: {
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        method: clientInfo.method,
        ...(clientInfo.deviceFingerprint !== undefined
          ? { deviceFingerprint: clientInfo.deviceFingerprint }
          : {}),
      },
    });

    if (result.success) {
      return {
        success: true,
        data: result.data.record,
        newToken: result.data.newToken,
        newCsrfToken: result.newCsrfToken,
        clearCsrfToken: result.clearCsrfToken,
      };
    }

    return {
      success: false,
      error: {
        message: result.error?.message || "Rotation failed",
        httpCode: result.httpCode || 401,
      },
      clearCsrfToken: result.clearCsrfToken,
    };
  };
}

export function buildValidateFn(
  service: ISessionService,
  options?: {
    /**
     * Which service method to call. Default: "validate".
     * Use "rotate" to propagate newCsrfToken during token rotation.
     */
    mode?: "validate" | "rotate";
  },
): ValidateFunction {
  if (options?.mode === "rotate") {
    return buildRotateValidateFn(service);
  }
  return buildDefaultValidateFn(service);
}
