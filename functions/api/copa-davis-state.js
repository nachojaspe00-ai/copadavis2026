export async function onRequestGet(context) {
  const data = await context.env.COPA_DAVIS_STATE.get('state');

  return new Response(
    data || JSON.stringify({
      version: 1,
      teams: [],
      players: [],
      dates: [],
      settings: {}
    }),
    {
      headers: {
        'content-type': 'application/json;charset=UTF-8'
      }
    }
  );
}

export async function onRequestPut(context) {
  const body = await context.request.text();

  try {
    JSON.parse(body);
  } catch {
    return new Response('JSON inválido', { status: 400 });
  }

  await context.env.COPA_DAVIS_STATE.put('state', body);

  return new Response(
    JSON.stringify({ ok: true }),
    {
      headers: {
        'content-type': 'application/json'
      }
    }
  );
}
