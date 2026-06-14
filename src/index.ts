import PostalMime from 'postal-mime'

interface Env {
  FORWARDING_KV: KVNamespace
  MAIL_API_BASE_URL: string
  ALLOWED_ORIGIN: string
  RESEND_API_KEY: string
  FORWARD_AUTH_TOKEN: string
  FROM_EMAIL: string
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

interface ForwardingRecord {
  sourceEmail: string
  targetEmail: string
  verified: boolean
  enabled: boolean
  createdAt: string
  updatedAt: string
}

interface VerifyRecord {
  sourceEmail: string
  targetEmail: string
  createdAt: string
}

class ResponseError extends Error {
  status: number

  constructor(message: string, status = 500) {
    super(message)
    this.status = status
  }
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

const html = (body: string, status = 200) => {
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8' }
  })
}

const corsHeaders = (request: Request, env: Env) => {
  const origin = request.headers.get('origin') || ''
  const allowOrigin = origin === env.ALLOWED_ORIGIN ? origin : env.ALLOWED_ORIGIN
  return {
    'access-control-allow-origin': allowOrigin,
    'access-control-allow-methods': 'GET,POST,DELETE,OPTIONS',
    'access-control-allow-headers': 'authorization,content-type,x-mail-from,x-mail-to',
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

const generateToken = () => {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
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

// ─── KV ───

const forwardingKey = (sourceEmail: string) => `forwarding:${sourceEmail}`
const verifyKey = (token: string) => `verify:${token}`

const getRecord = async (env: Env, sourceEmail: string) => {
  return env.FORWARDING_KV.get<ForwardingRecord>(forwardingKey(sourceEmail), 'json')
}

const putRecord = async (env: Env, record: ForwardingRecord) => {
  await env.FORWARDING_KV.put(forwardingKey(record.sourceEmail), JSON.stringify(record))
}

const getVerifyRecord = async (env: Env, token: string) => {
  return env.FORWARDING_KV.get<VerifyRecord>(verifyKey(token), 'json')
}

const putVerifyRecord = async (env: Env, token: string, record: VerifyRecord) => {
  // 验证记录 24 小时过期
  await env.FORWARDING_KV.put(verifyKey(token), JSON.stringify(record), { expirationTtl: 86400 })
}

const deleteVerifyRecord = async (env: Env, token: string) => {
  await env.FORWARDING_KV.delete(verifyKey(token))
}

// ─── Resend API ───

const sendViaResend = async (env: Env, body: Record<string, unknown>) => {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    const err = await res.text()
    throw new ResponseError(`Resend API 失败: ${err}`, 502)
  }
  return res.json()
}

// ─── 验证邮件模板 ───

const verifyEmailHtml = (verifyUrl: string) => `
<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:20px;">
  <h2 style="color:#1e293b;">GGU Mail 邮箱转发验证</h2>
  <p style="color:#475569;line-height:1.6;">
    您正在将 GGU 邮箱的邮件转发到此邮箱。<br>
    请点击下方按钮完成验证：
  </p>
  <a href="${verifyUrl}"
     style="display:inline-block;padding:12px 24px;background:#3b82f6;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;margin:16px 0;">
    验证邮箱
  </a>
  <p style="color:#94a3b8;font-size:12px;">
    如果按钮无法点击，请复制以下链接到浏览器：<br>
    <a href="${verifyUrl}" style="color:#3b82f6;">${verifyUrl}</a>
  </p>
  <p style="color:#94a3b8;font-size:12px;">
    此验证链接 24 小时内有效。如果不是您本人操作，请忽略此邮件。
  </p>
</div>
`

const verifyEmailText = (verifyUrl: string) =>
  `GGU Mail 邮箱转发验证\n\n` +
  `您正在将 GGU 邮箱的邮件转发到此邮箱。\n` +
  `请复制以下链接到浏览器完成验证：\n\n${verifyUrl}\n\n` +
  `此验证链接 24 小时内有效。如果不是您本人操作，请忽略此邮件。\n`

// ─── 验证成功页面 ───

const verifySuccessHtml = `
<!DOCTYPE html>
<html lang="zh">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"><title>验证成功</title></head>
<body style="font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f8fafc;">
  <div style="text-align:center;padding:40px;">
    <div style="font-size:48px;margin-bottom:16px;">✅</div>
    <h1 style="color:#1e293b;font-size:24px;">邮箱验证成功</h1>
    <p style="color:#64748b;margin-top:8px;">请返回 GGU Mail 页面点击"我已完成验证，启用转发"。</p>
  </div>
</body>
</html>
`

const verifyFailHtml = (message: string) => `
<!DOCTYPE html>
<html lang="zh">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"><title>验证失败</title></head>
<body style="font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f8fafc;">
  <div style="text-align:center;padding:40px;">
    <div style="font-size:48px;margin-bottom:16px;">❌</div>
    <h1 style="color:#1e293b;font-size:24px;">验证失败</h1>
    <p style="color:#64748b;margin-top:8px;">${message}</p>
  </div>
</body>
</html>
`

// ─── 转发通知模板 ───

const forwardNoticeHtml = (originalFrom: string, originalTo: string) => `
<div style="background:#f0f4f8;border-left:4px solid #3b82f6;padding:12px 16px;margin-bottom:20px;font-size:13px;color:#475569;">
  <strong>=== Forwarded by GGU Mail ===</strong><br>
  此邮件由 GGU-Mail 进行转发<br>
  Original From: ${originalFrom}<br>
  Original To: ${originalTo}<br>
  您可以在 <a href="https://ggu.edu.kg/mail/">https://ggu.edu.kg/mail/</a> 查看原始邮件<br>
  为避免我们的邮件转发系统被您的邮件服务商错误标记为垃圾邮件，我们强烈建议您将我们的转发邮箱加入您的白名单并回复此邮件任意内容！
</div>
`

const forwardNoticeText = (originalFrom: string, originalTo: string) =>
  `=== Forwarded by GGU Mail ===\n` +
  `此邮件由 GGU-Mail 进行转发\n` +
  `Original From: ${originalFrom}\n` +
  `Original To: ${originalTo}\n` +
  `您可以在 https://ggu.edu.kg/mail/ 查看原始邮件\n` +
  `为避免我们的邮件转发系统被您的邮件服务商错误标记为垃圾邮件，我们强烈建议您将我们的转发邮箱加入您的白名单并回复此邮件任意内容！\n\n`

// ─── POST /forward（cloud-mail 调用）───

const handleForward = async (request: Request, env: Env) => {
  const authHeader = request.headers.get('authorization')?.trim()
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : authHeader
  if (token !== env.FORWARD_AUTH_TOKEN) {
    throw new ResponseError('Unauthorized', 401)
  }

  const originalFrom = request.headers.get('x-mail-from') || ''
  const originalTo = request.headers.get('x-mail-to') || ''

  if (!originalTo) {
    throw new ResponseError('缺少 X-Mail-To', 400)
  }

  const recipientEmail = assertEmail(originalTo)
  const record = await getRecord(env, recipientEmail)

  if (!record || !record.enabled || !record.targetEmail) {
    return { forwarded: false, reason: '未配置或未启用' }
  }

  const rawMime = await request.text()
  const parsed = await PostalMime.parse(rawMime)

  const fromName = parsed.from?.name || 'GGU Mail'
  const fromAddress = env.FROM_EMAIL || 'relay@mailforwarding.ggu.edu.kg'
  const replyTo = parsed.from?.address || originalFrom

  const htmlBody = parsed.html || ''
  const textBody = parsed.text || ''

  const attachments = (parsed.attachments || []).map(att => ({
    filename: att.filename || 'attachment',
    content: arrayBufferToBase64(att.content),
    content_type: att.mimeType || 'application/octet-stream'
  }))

  const resendBody: Record<string, unknown> = {
    from: `${fromName} <${fromAddress}>`,
    to: [record.targetEmail],
    reply_to: replyTo,
    subject: parsed.subject || '(无主题)',
    html: forwardNoticeHtml(originalFrom, originalTo) + htmlBody,
    text: forwardNoticeText(originalFrom, originalTo) + textBody,
    headers: {
      'X-Original-From': originalFrom,
      'X-Original-To': originalTo
    }
  }

  if (attachments.length > 0) {
    resendBody.attachments = attachments
  }

  await sendViaResend(env, resendBody)

  return { forwarded: true, target: record.targetEmail }
}

const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

// ─── GET /forwarding/status ───

const handleStatus = async (request: Request, env: Env) => {
  const sourceEmail = await getCurrentUserEmail(request, env)
  const record = await getRecord(env, sourceEmail)
  return {
    sourceEmail,
    targetEmail: record?.targetEmail || '',
    verified: Boolean(record?.verified),
    enabled: Boolean(record?.enabled)
  }
}

// ─── POST /forwarding/request ───

const handleRequestVerification = async (request: Request, env: Env) => {
  const sourceEmail = await getCurrentUserEmail(request, env)
  const body = await request.json<Record<string, unknown>>()
  const targetEmail = assertEmail(body.targetEmail)

  if (targetEmail === sourceEmail) {
    throw new ResponseError('目标邮箱不能与当前邮箱相同', 400)
  }

  const existing = await getRecord(env, sourceEmail)
  const now = Date.now()

  if (existing?.updatedAt && now - new Date(existing.updatedAt).getTime() < 60_000) {
    throw new ResponseError('请求过于频繁，请稍后再试', 429)
  }

  const token = generateToken()
  const origin = new URL(request.url).origin

  await putVerifyRecord(env, token, {
    sourceEmail,
    targetEmail,
    createdAt: new Date().toISOString()
  })

  // 如果已有记录，先标记为未验证未启用
  const time = new Date().toISOString()
  await putRecord(env, {
    sourceEmail,
    targetEmail,
    verified: false,
    enabled: false,
    createdAt: existing?.createdAt || time,
    updatedAt: time
  })

  const verifyUrl = `${origin}/forwarding/verify?token=${token}`

  await sendViaResend(env, {
    from: env.FROM_EMAIL || 'relay@mailforwarding.ggu.edu.kg',
    to: [targetEmail],
    subject: 'GGU Mail 邮箱转发验证',
    html: verifyEmailHtml(verifyUrl),
    text: verifyEmailText(verifyUrl)
  })

  return {
    sourceEmail,
    targetEmail,
    verified: false,
    enabled: false
  }
}

// ─── GET /forwarding/verify ───

const handleVerify = async (request: Request, env: Env) => {
  const url = new URL(request.url)
  const token = url.searchParams.get('token')

  if (!token) {
    return html(verifyFailHtml('缺少验证参数'), 400)
  }

  const verifyRecord = await getVerifyRecord(env, token)
  if (!verifyRecord) {
    return html(verifyFailHtml('验证链接无效或已过期'), 400)
  }

  const { sourceEmail, targetEmail } = verifyRecord

  const existing = await getRecord(env, sourceEmail)
  const time = new Date().toISOString()

  await putRecord(env, {
    sourceEmail,
    targetEmail,
    verified: true,
    enabled: existing?.enabled || false,
    createdAt: existing?.createdAt || time,
    updatedAt: time
  })

  await deleteVerifyRecord(env, token)

  return html(verifySuccessHtml)
}

// ─── POST /forwarding/activate ───

const handleActivate = async (request: Request, env: Env) => {
  const sourceEmail = await getCurrentUserEmail(request, env)
  const record = await getRecord(env, sourceEmail)

  if (!record || !record.targetEmail) {
    throw new ResponseError('请先提交目标邮箱', 400)
  }

  if (!record.verified) {
    return {
      sourceEmail,
      targetEmail: record.targetEmail,
      verified: false,
      enabled: false
    }
  }

  const nextRecord: ForwardingRecord = {
    ...record,
    enabled: true,
    updatedAt: new Date().toISOString()
  }
  await putRecord(env, nextRecord)

  return {
    sourceEmail,
    targetEmail: record.targetEmail,
    verified: true,
    enabled: true
  }
}

// ─── DELETE /forwarding ───

const handleDelete = async (request: Request, env: Env) => {
  const sourceEmail = await getCurrentUserEmail(request, env)
  const record = await getRecord(env, sourceEmail)
  if (!record) {
    return { sourceEmail, targetEmail: '', verified: false, enabled: false }
  }

  const nextRecord: ForwardingRecord = {
    ...record,
    enabled: false,
    updatedAt: new Date().toISOString()
  }
  await putRecord(env, nextRecord)

  return {
    sourceEmail,
    targetEmail: record.targetEmail,
    verified: record.verified,
    enabled: false
  }
}

// ─── Router ───

const route = async (request: Request, env: Env) => {
  const url = new URL(request.url)

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(request, env) })
  }

  if (url.pathname === '/forward' && request.method === 'POST') {
    return handleForward(request, env)
  }
  if (url.pathname === '/forwarding/status' && request.method === 'GET') {
    return handleStatus(request, env)
  }
  if (url.pathname === '/forwarding/request' && request.method === 'POST') {
    return handleRequestVerification(request, env)
  }
  if (url.pathname === '/forwarding/verify' && request.method === 'GET') {
    return handleVerify(request, env)
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
