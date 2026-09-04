export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/state') {
      if (request.method === 'GET') {
        const data = env.COPA_DAVIS_STATE ? await env.COPA_DAVIS_STATE.get('state') : null;
        return new Response(data || JSON.stringify({}), { headers: { 'content-type': 'application/json;charset=UTF-8' } });
      }
      if (request.method === 'PUT') {
        const body = await request.text();
        try { JSON.parse(body); } catch { return new Response('JSON inválido', { status: 400 }); }
        if (!env.COPA_DAVIS_STATE) return new Response(JSON.stringify({ok:false, message:'KV no configurado'}), {headers:{'content-type':'application/json'}, status:503});
        await env.COPA_DAVIS_STATE.put('state', body);
        return new Response(JSON.stringify({ok:true}), {headers:{'content-type':'application/json'}});
      }
      return new Response('Method Not Allowed', {status:405});
    }
    return env.ASSETS.fetch(request);
  }
};
