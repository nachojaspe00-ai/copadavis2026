```js
import {
  json,
  nowIso,
  randomBytes,
  b64url,
  sha256,
  sessionCookie,
  clearSessionCookie,
  requireAdmin,
  cleanSessions
} from './_utils.js';

export async function onRequestGet({ request, env }) {
  return json({
    authenticated: !!(await requireAdmin(request, env))
  });
}

export async function onRequestPost({ request, env }) {
  const body = await request.json().catch(() => ({}));
  const action = body.action;

  await cleanSessions(env);

  // LOGOUT
  if (action === 'logout') {
    return new Response(null, {
      status: 204,
      headers: {
        'Set-Cookie': clearSessionCookie()
      }
    });
  }

  // LOGIN
  if (action === 'login') {
    const pin = String(body.pin || '');

    if (!/^\d{4,8}$/.test(pin)) {
      return json(
        { error: 'El PIN debe tener entre 4 y 8 números.' },
        400
      );
    }

    // ADMIN_PIN es la fuente de verdad.
    if (!env.ADMIN_PIN) {
      return json(
        {
          error: 'ADMIN_PIN no está configurado en Cloudflare.'
        },
        500
      );
    }

    const configuredPin = String(env.ADMIN_PIN);

    // Comprobar PIN
    if (pin !== configuredPin) {
      return json(
        { error: 'PIN incorrecto.' },
        401
      );
    }

    // PIN CORRECTO
    // Generamos una sesión nueva.
    const token = b64url(randomBytes(32));

    const tokenHash = b64url(
      await sha256(
        new TextEncoder().encode(token)
      )
    );

    const exp = Date.now() + 7 * 86400000;

    await env.DB
      .prepare(
        'INSERT INTO admin_sessions (token_hash, expires_at) VALUES (?, ?)'
      )
      .bind(tokenHash, exp)
      .run();

    return json(
      { ok: true },
      200,
      {
        'Set-Cookie': sessionCookie(token)
      }
    );
  }

  return json(
    { error: 'Acción no válida.' },
    400
  );
}
```
