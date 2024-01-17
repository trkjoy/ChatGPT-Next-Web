import { NextRequest } from "next/server";
import { getServerSideConfig } from "../config/server";
import md5 from "spark-md5";
import { ACCESS_CODE_PREFIX, ModelProvider } from "../constant";

function getIP(req: NextRequest) {
  let ip = req.ip ?? req.headers.get("x-real-ip");
  const forwardedFor = req.headers.get("x-forwarded-for");

  if (!ip && forwardedFor) {
    ip = forwardedFor.split(",").at(0) ?? "";
  }

  return ip;
}

function parseApiKey(bearToken: string) {
  const token = bearToken.trim().replaceAll("Bearer ", "").trim();
  const isApiKey = !token.startsWith(ACCESS_CODE_PREFIX);

  return {
    accessCode: isApiKey ? "" : token.slice(ACCESS_CODE_PREFIX.length),
    apiKey: isApiKey ? token : "",
  };
}

export function auth(req: NextRequest, modelProvider: ModelProvider) {
  const authName = req.headers.get("X-Name") ?? "";
  const authToken = req.headers.get("X-Token") ?? "";
  const authorization = req.headers.get("Authorization") ?? "";
  const serverConfig = getServerSideConfig();

  // check if it is openai api key or user token
  let { accessCode, apiKey: token } = parseApiKey(authorization);
  if(authName != "" && authToken != ""){
    token = ""
    const sign = md5.hash( `${authName}&${authToken}&hlcygpt`)
    if(sign != accessCode){
      return {
        error: true,
        msg: "~~ sorry "+authName+",wrong access code:"+accessCode,
      };
    }
  }else{
        //非后台访问不可用
        return {
          error: true,
          msg:"No Access ~~",
        };
  }
  // if user does not provide an api key, inject system api key
  if (!token) {
    const systemApiKey =
    modelProvider === ModelProvider.GeminiPro
      ? serverConfig.googleApiKey
      : serverConfig.isAzure
      ? serverConfig.azureApiKey
      : serverConfig.apiKey;
    if (systemApiKey) {
      console.log("[Auth] use system api key");
      req.headers.set("Authorization", `Bearer ${systemApiKey}`);
    } else {
      console.log("[Auth] admin did not provide an api key");
    }
  } else {
    console.log("[Auth] use user api key");
  }
  return {
    error: false,
  };
}
