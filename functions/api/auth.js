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
  cleanSessions,
  fromB64url
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

  if (action === 'logout') {
    return new Response(null, {
      status: 204,
      headers: {
        'Set-Cookie': clearSessionCookie()
      }
    });
  }

  if (action === 'login') {
    const pin = String(body.pin || '');

    if (!/^\d{4,8}$/.test(pin)) {
      return json(
        { error: 'El PIN debe tener entre 4 y 8 números.' },
        400
      );
    }

    let cfg = await env.DB
      .prepare('SELECT * FROM admin_config WHERE id=1')
      .first();

    // Primera configuración del administrador
    if (!cfg) {
      if (!env.ADMIN_PIN) {
        return json(
          { error: 'ADMIN_PIN no está configurado en Cloudflare.' },
          500
        );
      }

      const initial = String(env.ADMIN_PIN);
      const salt = randomBytes(16);
      const hash = await pbkdf2(
        initial,
        salt,
        MAX_ITERATIONS
      );

      await env.DB
        .prepare(
          `INSERT OR IGNORE INTO admin_config
          (id, pin_hash, salt, iterations, updated_at)
          VALUES (1, ?, ?, ?, ?)`
        )
        .bind(
          b64url(hash),
          b64url(salt),
          MAX_ITERATIONS,
          nowIso()
        )
        .run();

      cfg = await env.DB
        .prepare('SELECT * FROM admin_config WHERE id=1')
        .first();
    }

    /*
     * Si quedó guardada una configuración anterior
     * con 120000 iteraciones, la regeneramos usando
     * el ADMIN_PIN actual y el límite compatible con Cloudflare.
     */
    if (Number(cfg.iterations) > MAX_ITERATIONS) {
      if (!env.ADMIN_PIN) {
        return json(
          {
            error:
              'La configuración del PIN necesita actualizarse. Configurá ADMIN_PIN en Cloudflare.'
          },
          500
        );
      }

      const initial = String(env.ADMIN_PIN);
      const salt = randomBytes(16);
      const hash = await pbkdf2(
        initial,
        salt,
        MAX_ITERATIONS
      );

      await env.DB
        .prepare(
          `UPDATE admin_config
           SET pin_hash=?, salt=?, iterations=?, updated_at=?
           WHERE id=1`
        )
        .bind(
          b64url(hash),
          b64url(salt),
          MAX_ITERATIONS,
          nowIso()
        )
        .run();

      cfg = await env.DB
        .prepare('SELECT * FROM admin_config WHERE id=1')
        .first();
    }

    const hash = await pbkdf2(
      pin,
      fromB64url(cfg.salt),
      Number(cfg.iterations)
    );

    if (b64url(hash) !== cfg.pin_hash) {
      return json(
        { error: 'PIN incorrecto.' },
        401
      );
    }

    const token = b64url(randomBytes(32));

    const tokenHash = b64url(
      await sha256(
        new TextEncoder().encode(token)
      )
    );

    const exp = Date.now() + 7 * 86400000;

    await env.DB
      .prepare(
        'INSERT INTO admin_sessions(token_hash,expires_at) VALUES(?,?)'
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
