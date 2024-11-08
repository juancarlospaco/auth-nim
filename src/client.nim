import std/[httpclient, json, uri, assertions]

type
  SyncAuthClient* = object
    url*: string             # https://github.com/supabase/functions-js/blob/19512a44aa3b8e4ea89a825899a4e1b2223368af/src/FunctionsClient.ts#L27
    client: HttpClient       # https://github.com/supabase/functions-js/blob/19512a44aa3b8e4ea89a825899a4e1b2223368af/src/FunctionsClient.ts#L30

  AsyncAuthClient* = object
    url*: string             # https://github.com/supabase/functions-js/blob/19512a44aa3b8e4ea89a825899a4e1b2223368af/src/FunctionsClient.ts#L27
    client: AsyncHttpClient  # https://github.com/supabase/functions-js/blob/19512a44aa3b8e4ea89a825899a4e1b2223368af/src/FunctionsClient.ts#L30

template is_ok_arg(url, apiKey: string) =
  assert url.len > 0, "url must be a valid HTTP URL string"
  assert apiKey.len > 0, "apiKey must be a valid JWT string"

proc close*(self: SyncAuthClient | AsyncAuthClient) {.inline.} = self.client.close()

proc newSyncAuthClient*(url, apiKey: string; maxRedirects = 9.Positive; timeout: -1..int.high = -1; proxy: Proxy = nil): SyncAuthClient =
  is_ok_arg(url, apiKey)
  SyncAuthClient(url: url, client: newHttpClient(userAgent="supabase/functions-nim v" & NimVersion, maxRedirects=maxRedirects, timeout=timeout, proxy=proxy,
    headers=newHttpHeaders({"Content-Type": "application/json", "Authorization": "Bearer " & apiKey})
  ))

proc newAsyncAuthClient*(url, apiKey: string; maxRedirects = 9.Positive; timeout: -1..int.high = -1; proxy: Proxy = nil): AsyncAuthClient =
  is_ok_arg(url, apiKey)
  AsyncAuthClient(url: url, client: newAsyncHttpClient(userAgent="supabase/functions-nim v" & NimVersion, maxRedirects=maxRedirects, proxy=proxy,
    headers=newHttpHeaders({"Content-Type": "application/json", "Authorization": "Bearer " & apiKey})
  ))

template api(endpoint: string; metod: static[HttpMethod]; headers: HttpHeaders; body: openArray[(string, string)]): untyped =
  self.client.request(url = self.url & endpoint, metod = metod, headers = headers, body = if body.len > 0: $(%*body) else: "")

# Supabase Auth API.

proc createUser*(self: SyncAuthClient | AsyncAuthClient; body: openArray[(string, string)]): auto =
  api(endpoint = "/admin/users", metod = HttpPost, headers = nil, body = body)

proc listUsers*(self: SyncAuthClient | AsyncAuthClient): auto =
  api(endpoint = "/admin/users", metod = HttpGet, headers = nil, body = {})

proc signUpWithEmail*(self: SyncAuthClient | AsyncAuthClient; email, password, redirectTo, data: string): auto =
  api(endpoint = "/signup" & (if redirectTo.len > 0: "?redirect_to=" & encodeUrl(redirectTo) else: ""), metod = HttpPost, headers = nil, body = {"email": email, "password": password, "data": data})

proc signUpWithEmail*(self: SyncAuthClient | AsyncAuthClient; email, password, redirectTo: string): auto =
  api(endpoint = "/signup" & (if redirectTo.len > 0: "?redirect_to=" & encodeUrl(redirectTo) else: ""), metod = HttpPost, headers = nil, body = {"email": email, "password": password})

proc signUpWithPhone*(self: SyncAuthClient | AsyncAuthClient; phone, password, redirectTo, data: string): auto =
  api(endpoint = "/signup" & (if redirectTo.len > 0: "?redirect_to=" & encodeUrl(redirectTo) else: ""), metod = HttpPost, headers = nil, body = {"phone": phone, "password": password, "data": data})

proc signUpWithPhone*(self: SyncAuthClient | AsyncAuthClient; phone, password, redirectTo: string): auto =
  api(endpoint = "/signup" & (if redirectTo.len > 0: "?redirect_to=" & encodeUrl(redirectTo) else: ""), metod = HttpPost, headers = nil, body = {"phone": phone, "password": password})

proc signInWithEmail*(self: SyncAuthClient | AsyncAuthClient; email, password, redirectTo: string): auto =
  api(endpoint = "/token?redirect_to=" & encodeUrl(redirectTo), metod = HttpPost, headers = nil, body = {"email": email, "password": password})

proc signInWithPhone*(self: SyncAuthClient | AsyncAuthClient; phone, password, redirectTo: string): auto =
  api(endpoint = "/token?redirect_to=" & encodeUrl(redirectTo), metod = HttpPost, headers = nil, body = {"phone": phone, "password": password})

proc sendMagicLinkEmail*(self: SyncAuthClient | AsyncAuthClient; email, redirectTo: string; createUser: bool): auto =
  api(endpoint = "/magiclink?redirect_to=" & encodeUrl(redirectTo), metod = HttpPost, headers = nil, body = {"email": email, "create_user": createUser})

proc sendMobileOtp*(self: SyncAuthClient | AsyncAuthClient; phone: string; createUser: bool): auto =
  api(endpoint = "/otp", metod = HttpPost, headers = nil, body = {"phone": phone, "create_user": createUser})

proc verifyMobileOtp*(self: SyncAuthClient | AsyncAuthClient; phone, token, redirectTo: string): auto =
  api(endpoint = "/verify", metod = HttpPost, headers = nil, body = {"phone": phone, "token": token, "type": "sms", redirectTo: encodeUrl(redirectTo)})

proc verifyMobileOtp*(self: SyncAuthClient | AsyncAuthClient; phone, token: string): auto =
  api(endpoint = "/verify", metod = HttpPost, headers = nil, body = {"phone": phone, "token": token, "type": "sms"})

proc inviteUserByEmail*(self: SyncAuthClient | AsyncAuthClient; email, redirectTo, data: string): auto =
  api(endpoint = "/invite?redirect_to=" & encodeUrl(redirectTo), metod = HttpPost, headers = nil, body = {"email": email, "data": data})

proc inviteUserByEmail*(self: SyncAuthClient | AsyncAuthClient; email, redirectTo: string): auto =
  api(endpoint = "/invite?redirect_to=" & encodeUrl(redirectTo), metod = HttpPost, headers = nil, body = {"email": email})

proc resetPasswordForEmail*(self: SyncAuthClient | AsyncAuthClient; email, redirectTo: string): auto =
  api(endpoint = "/recover?redirect_to=" & encodeUrl(redirectTo), metod = HttpPost, headers = nil, body = {"email": email})

proc signOut*(self: SyncAuthClient | AsyncAuthClient; jwt: string): auto =
  api(endpoint = "/logout", metod = HttpPost, headers = nil, body = {})

proc getUrlForProvider*(self: SyncAuthClient | AsyncAuthClient; provider, redirectTo, scopes: string): string =
  self.url & "/authorize?provider=" & encodeUrl(provider) & "&redirect_to=" & encodeUrl(redirectTo) & "&scopes=" & encodeUrl(scopes)

proc getUrlForProvider*(self: SyncAuthClient | AsyncAuthClient; provider, redirectTo: string): string =
  self.url & "/authorize?provider=" & encodeUrl(provider) & "&redirect_to=" & encodeUrl(redirectTo)

proc getUrlForProvider*(self: SyncAuthClient | AsyncAuthClient; provider: string): string =
  self.url & "/authorize?provider=" & encodeUrl(provider)

proc getUser*(self: SyncAuthClient | AsyncAuthClient; jwt: string): auto =
  api(endpoint = "/user", metod = HttpGet, headers = nil, body = {})

proc updateUser*(self: SyncAuthClient | AsyncAuthClient; jwt: string): auto =
  api(endpoint = "/user", metod = HttpGet, headers = nil, body = {})

proc deleteUser*(self: SyncAuthClient | AsyncAuthClient; jwt: string): auto =
  api(endpoint = "/user", metod = HttpGet, headers = nil, body = {})

proc refreshAccessToken*(self: SyncAuthClient | AsyncAuthClient; refresh_token: string): auto =
  api(endpoint = "/user", metod = HttpGet, headers = nil, body = {})

proc generateLink*(self: SyncAuthClient | AsyncAuthClient; email, password, redirectTo, data: string): auto =
  api(endpoint = "/user", metod = HttpGet, headers = nil, body = {})

proc setAuthCookie*(self: SyncAuthClient | AsyncAuthClient; req, res: string): auto =
  api(endpoint = "/user", metod = HttpGet, headers = nil, body = {})

proc getUserByCookie*(self: SyncAuthClient | AsyncAuthClient; req: string): auto =
  api(endpoint = "/user", metod = HttpGet, headers = nil, body = {})

proc getProjectConfig*(self: SyncAuthClient | AsyncAuthClient): auto =
  api(endpoint = "/config/auth", metod = HttpGet, headers = nil, body = {})

proc setProjectConfig*(self: SyncAuthClient | AsyncAuthClient; newAuthConfig: JsonNode): auto =
  api(endpoint = "/config/auth", metod = HttpPatch, headers = nil, body = newAuthConfig)
