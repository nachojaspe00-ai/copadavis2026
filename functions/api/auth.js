```js
import {
  json,
  nowIso,
  randomBytes,
  b64url,
  sha256,
  pbkdf2,
  sessionCookie,
  clearSessionCookie,
  requireAdmin,
  cleanSessions
} from './_utils.js';

const MAX_ITERATIONS = 100000;

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

    // ---------------------------------------------------------
    // EL ADMIN_PIN DE CLOUDFLARE ES LA FUENTE DE VERDAD
    // ---------------------------------------------------------

    if (!env.ADMIN_PIN) {
      return json(
        {
          error:
            'ADMIN_PIN no está configurado en Cloudflare.'
        },
        500
      );
    }

    const configuredPin = String(env.ADMIN_PIN);

    // Comparamos el PIN ingresado con el secreto de Cloudflare.
    if (pin !== configuredPin) {
      return json(
        { error: 'PIN incorrecto.' },
        401
      );
    }

    // ---------------------------------------------------------
    // PIN CORRECTO
    // ---------------------------------------------------------

    // Generamos/actualizamos la configuración almacenada en D1.
    const salt = randomBytes(16);

    const hash = await pbkdf2(
      configuredPin,
      salt,
      MAX_ITERATIONS
    );

    await env.DB
      .prepare(
        `INSERT INTO admin_config
          (id, pin_hash, salt, iterations, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           pin_hash=excluded.pin_hash,
           salt=excluded.salt,
           iterations=excluded.iterations,
           updated_at=excluded.updated_at`
      )
      .bind(
        1,
        b64url(hash),
        b64url(salt),
        MAX_ITERATIONS,
        nowIso()
      )
      .run();

    // ---------------------------------------------------------
    // CREAR SESIÓN
    // ---------------------------------------------------------

    const token = b64url(randomBytes(32));

    const tokenHash = b64url(
      await sha256(
        new TextEncoder().encode(token)
      )
    );

    const exp = Date.now() + 7 * 86400000;

    await env.DB
      .prepare(
        `INSERT INTO admin_sessions
         (token_hash, expires_at)
         VALUES (?, ?)`
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
