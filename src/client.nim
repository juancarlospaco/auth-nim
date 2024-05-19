import std/httpclient

type
  SyncFunctionsClient* = object
    url*: string             # https://github.com/supabase/functions-js/blob/19512a44aa3b8e4ea89a825899a4e1b2223368af/src/FunctionsClient.ts#L27
    client: HttpClient       # https://github.com/supabase/functions-js/blob/19512a44aa3b8e4ea89a825899a4e1b2223368af/src/FunctionsClient.ts#L30

  AsyncFunctionsClient* = object
    url*: string             # https://github.com/supabase/functions-js/blob/19512a44aa3b8e4ea89a825899a4e1b2223368af/src/FunctionsClient.ts#L27
    client: AsyncHttpClient  # https://github.com/supabase/functions-js/blob/19512a44aa3b8e4ea89a825899a4e1b2223368af/src/FunctionsClient.ts#L30

  SFResponseType* {.pure.} = enum  # Supabase Functions "Content-Type". HTML is not supported.
    Json = "application/json"
    Text = "text/plain"

proc close*(self: SyncFunctionsClient | AsyncFunctionsClient) {.inline.} = self.client.close()

proc newSyncFunctionsClient*(url, apiKey: string; maxRedirects = 9.Positive; timeout: -1..int.high = -1; proxy: Proxy = nil): SyncFunctionsClient =
  SyncFunctionsClient(url: url, client: newHttpClient(userAgent="supabase/functions-nim v" & NimVersion, maxRedirects=maxRedirects, timeout=timeout, proxy=proxy,
    headers=newHttpHeaders({"Content-Type": "application/json", "Authorization": "Bearer " & apiKey})
  ))

proc newAsyncFunctionsClient*(url, apiKey: string; maxRedirects = 9.Positive; timeout: -1..int.high = -1; proxy: Proxy = nil): AsyncFunctionsClient =
  AsyncFunctionsClient(url: url, client: newAsyncHttpClient(userAgent="supabase/functions-nim v" & NimVersion, maxRedirects=maxRedirects, proxy=proxy,
    headers=newHttpHeaders({"Content-Type": "application/json", "Authorization": "Bearer " & apiKey})
  ))

proc invoke*(self: SyncFunctionsClient | AsyncFunctionsClient; functionName: string, body = ""; responseType = SFResponseType.Json; region = SFRegion.Any; httpMethod = HttpPost; multipart: MultipartData = nil; apiKey = ""): auto =
  # https://github.com/supabase/functions-js/blob/19512a44aa3b8e4ea89a825899a4e1b2223368af/src/FunctionsClient.ts#L37-L39
  if apiKey.len > 100: self.client.headers["Authorization"] = "Bearer " & apiKey
  # https://github.com/supabase/functions-js/blob/098537a0f5e1c2b2aca8891625c4deca846b0591/src/FunctionsClient.ts#L85-L86
  if responseType != SFResponseType.Json: self.client.headers["Content-Type"] = $responseType
  # https://github.com/supabase/functions-js/blob/098537a0f5e1c2b2aca8891625c4deca846b0591/src/FunctionsClient.ts#L60-L62
  if region != SFRegion.Any: self.client.headers["x-region"] = $region
  # https://github.com/supabase/functions-js/blob/19512a44aa3b8e4ea89a825899a4e1b2223368af/src/types.ts#L70
  result = self.client.request(url = self.url & '/' & functionName, httpMethod = httpMethod, body = body, multipart = multipart)
