interface Env {
  CF_API_TOKEN: string
  CF_ACCOUNT_ID: string
  CF_ZONE_ID: string
  MAIL_API_BASE_URL: string
  ALLOWED_ORIGIN: string
  FORWARDING_KV: KVNamespace
}

interface MailUserResponse {
  email?: string
  account?: {
    email?: string
  }
}

interface MailEnvelope<T> {
  code?: number
  message?: string
  data?: T
}

interface CloudflareEnvelope<T> {
  success: boolean
  errors: Array<{ message?: string }>
  result: T
}

interface DestinationAddress {
  id: string
  email: string
  verified: string | null
}

interface RoutingRule {
  id: string
  enabled: boolean
}

interface ForwardingRecord {
  sourceEmail: string
  targetEmail: string
  destinationId: string
  ruleId: string | null
  verified: boolean
  enabled: boolean
  lastRequestAt?: number
  createdAt: string
  updatedAt: string
}

const json = (data: unknown, status = 200, headers: HeadersInit = {}) => {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...headers
    }
  })
}

const corsHeaders = (request: Request, env: Env) => {
  const origin = request.headers.get('origin') || ''
  const allowOrigin = origin === env.ALLOWED_ORIGIN ? origin : env.ALLOWED_ORIGIN
  return {
    'access-control-allow-origin': allowOrigin,
    'access-control-allow-methods': 'GET,POST,DELETE,OPTIONS',
    'access-control-allow-headers': 'authorization,content-type',
    'access-control-max-age': '86400'
  }
}

const normalizeBaseUrl = (value: string) => value.replace(/\/$/, '')

const assertEmail = (value: unknown) => {
  if (typeof value !== 'string') {
    throw new ResponseError('邮箱格式不正确', 400)
  }
  const email = value.trim().toLowerCase()
  if (email.length > 254 || /[\r\n\0]/.test(email) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new ResponseError('邮箱格式不正确', 400)
  }
  return email
}

class ResponseError extends Error {
  status: number

  constructor(message: string, status = 500) {
    super(message)
    this.status = status
  }
}

const getAuthToken = (request: Request) => {
  const token = request.headers.get('authorization')?.trim()
  if (!token) {
    throw new ResponseError('未登录', 401)
  }
  return token.startsWith('Bearer ') ? token.slice(7).trim() : token
}

const getCurrentUserEmail = async (request: Request, env: Env) => {
  const token = getAuthToken(request)
  const res = await fetch(`${normalizeBaseUrl(env.MAIL_API_BASE_URL)}/my/loginUserInfo`, {
    headers: {
      Authorization: token
    }
  })
  if (!res.ok) {
    throw new ResponseError('登录状态已失效', 401)
  }

  const payload = await res.json<MailEnvelope<MailUserResponse> | MailUserResponse>()
  const data = 'code' in payload ? payload.data : payload
  const email = data?.email || data?.account?.email
  if (!email) {
    throw new ResponseError('无法获取当前邮箱', 403)
  }
  return assertEmail(email)
}

const cfFetch = async <T>(env: Env, path: string, init: RequestInit = {}) => {
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    ...init,
    headers: {
      'Authorization': `Bearer ${env.CF_API_TOKEN}`,
      'content-type': 'application/json',
      ...init.headers
    }
  })
  const payload = await res.json<CloudflareEnvelope<T>>()
  if (!res.ok || !payload.success) {
    throw new ResponseError(payload.errors?.[0]?.message || 'Cloudflare API 请求失败', res.status || 502)
  }
  return payload.result
}

const forwardingKey = (sourceEmail: string) => `forwarding:${sourceEmail}`

const getRecord = async (env: Env, sourceEmail: string) => {
  return env.FORWARDING_KV.get<ForwardingRecord>(forwardingKey(sourceEmail), 'json')
}

const putRecord = async (env: Env, record: ForwardingRecord) => {
  await env.FORWARDING_KV.put(forwardingKey(record.sourceEmail), JSON.stringify(record))
}

const findDestinationByEmail = async (env: Env, email: string) => {
  const result = await cfFetch<DestinationAddress[]>(
    env,
    `/accounts/${env.CF_ACCOUNT_ID}/email/routing/addresses?per_page=100`
  )
  return result.find(item => item.email.toLowerCase() === email.toLowerCase()) || null
}

const createDestination = async (env: Env, targetEmail: string) => {
  const existing = await findDestinationByEmail(env, targetEmail)
  if (existing) {
    return existing
  }
  return cfFetch<DestinationAddress>(env, `/accounts/${env.CF_ACCOUNT_ID}/email/routing/addresses`, {
    method: 'POST',
    body: JSON.stringify({ email: targetEmail })
  })
}

const getDestination = async (env: Env, id: string) => {
  return cfFetch<DestinationAddress>(env, `/accounts/${env.CF_ACCOUNT_ID}/email/routing/addresses/${id}`)
}

const upsertRule = async (env: Env, record: ForwardingRecord) => {
  const body = {
    actions: [
      {
        type: 'forward',
        value: [record.targetEmail]
      }
    ],
    matchers: [
      {
        type: 'literal',
        field: 'to',
        value: record.sourceEmail
      }
    ],
    enabled: true,
    name: `GGU forward: ${record.sourceEmail} -> ${record.targetEmail}`
  }

  if (record.ruleId) {
    return cfFetch<RoutingRule>(env, `/zones/${env.CF_ZONE_ID}/email/routing/rules/${record.ruleId}`, {
      method: 'PUT',
      body: JSON.stringify(body)
    })
  }

  return cfFetch<RoutingRule>(env, `/zones/${env.CF_ZONE_ID}/email/routing/rules`, {
    method: 'POST',
    body: JSON.stringify(body)
  })
}

const disableRule = async (env: Env, record: ForwardingRecord) => {
  if (!record.ruleId) return null
  return cfFetch<RoutingRule>(env, `/zones/${env.CF_ZONE_ID}/email/routing/rules/${record.ruleId}`, {
    method: 'PUT',
    body: JSON.stringify({
      actions: [
        {
          type: 'forward',
          value: [record.targetEmail]
        }
      ],
      matchers: [
        {
          type: 'literal',
          field: 'to',
          value: record.sourceEmail
        }
      ],
      enabled: false,
      name: `GGU forward: ${record.sourceEmail} -> ${record.targetEmail}`
    })
  })
}

const publicRecord = (sourceEmail: string, record: ForwardingRecord | null) => ({
  sourceEmail,
  targetEmail: record?.targetEmail || '',
  verified: Boolean(record?.verified),
  enabled: Boolean(record?.enabled)
})

const handleStatus = async (request: Request, env: Env) => {
  const sourceEmail = await getCurrentUserEmail(request, env)
  const record = await getRecord(env, sourceEmail)
  if (!record?.destinationId) {
    return publicRecord(sourceEmail, null)
  }

  const destination = await getDestination(env, record.destinationId)
  const nextRecord = {
    ...record,
    verified: Boolean(destination.verified),
    updatedAt: new Date().toISOString()
  }
  await putRecord(env, nextRecord)
  return publicRecord(sourceEmail, nextRecord)
}

const handleRequest = async (request: Request, env: Env) => {
  const sourceEmail = await getCurrentUserEmail(request, env)
  const body = await request.json<Record<string, unknown>>()
  const targetEmail = assertEmail(body.targetEmail)
  const existing = await getRecord(env, sourceEmail)
  const now = Date.now()

  if (existing?.lastRequestAt && now - existing.lastRequestAt < 60_000) {
    throw new ResponseError('请求过于频繁，请稍后再试', 429)
  }

  const destination = await createDestination(env, targetEmail)
  const time = new Date().toISOString()
  const record: ForwardingRecord = {
    sourceEmail,
    targetEmail,
    destinationId: destination.id,
    ruleId: existing?.ruleId || null,
    verified: Boolean(destination.verified),
    enabled: false,
    lastRequestAt: now,
    createdAt: existing?.createdAt || time,
    updatedAt: time
  }
  await putRecord(env, record)
  return publicRecord(sourceEmail, record)
}

const handleActivate = async (request: Request, env: Env) => {
  const sourceEmail = await getCurrentUserEmail(request, env)
  const record = await getRecord(env, sourceEmail)
  if (!record) {
    throw new ResponseError('请先提交目标邮箱', 400)
  }

  const destination = await getDestination(env, record.destinationId)
  if (!destination.verified) {
    const nextRecord = { ...record, verified: false, enabled: false, updatedAt: new Date().toISOString() }
    await putRecord(env, nextRecord)
    return publicRecord(sourceEmail, nextRecord)
  }

  const rule = await upsertRule(env, { ...record, verified: true })
  const nextRecord = {
    ...record,
    ruleId: rule.id,
    verified: true,
    enabled: true,
    updatedAt: new Date().toISOString()
  }
  await putRecord(env, nextRecord)
  return publicRecord(sourceEmail, nextRecord)
}

const handleDelete = async (request: Request, env: Env) => {
  const sourceEmail = await getCurrentUserEmail(request, env)
  const record = await getRecord(env, sourceEmail)
  if (!record) {
    return publicRecord(sourceEmail, null)
  }

  await disableRule(env, record)
  const nextRecord = { ...record, enabled: false, updatedAt: new Date().toISOString() }
  await putRecord(env, nextRecord)
  return publicRecord(sourceEmail, nextRecord)
}

const route = async (request: Request, env: Env) => {
  const url = new URL(request.url)

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(request, env) })
  }

  if (url.pathname === '/forwarding/status' && request.method === 'GET') {
    return handleStatus(request, env)
  }
  if (url.pathname === '/forwarding/request' && request.method === 'POST') {
    return handleRequest(request, env)
  }
  if (url.pathname === '/forwarding/activate' && request.method === 'POST') {
    return handleActivate(request, env)
  }
  if (url.pathname === '/forwarding' && request.method === 'DELETE') {
    return handleDelete(request, env)
  }

  throw new ResponseError('Not found', 404)
}

export default {
  async fetch(request: Request, env: Env) {
    const headers = corsHeaders(request, env)
    try {
      const result = await route(request, env)
      if (result instanceof Response) {
        for (const [key, value] of Object.entries(headers)) {
          result.headers.set(key, value)
        }
        return result
      }
      return json({ success: true, data: result }, 200, headers)
    } catch (error) {
      if (error instanceof ResponseError) {
        return json({ success: false, message: error.message }, error.status, headers)
      }
      return json({ success: false, message: 'Internal server error' }, 500, headers)
    }
  }
}
