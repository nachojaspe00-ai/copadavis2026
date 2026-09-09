import { json, nowIso, requireAdmin } from './_utils.js';
export async function onRequestGet({env}){
  try{const row=await env.DB.prepare('SELECT data,updated_at FROM app_state WHERE id=1').first();if(!row)return json({state:null,updatedAt:null});return json({state:JSON.parse(row.data),updatedAt:row.updated_at});}
  catch(e){return json({error:'No se pudo leer la base de datos.'},500)}
}
export async function onRequestPost({request,env}){
  try{if(!(await requireAdmin(request,env)))return json({error:'No autorizado.'},401);const body=await request.json();if(!body||typeof body.state!=='object')return json({error:'Estado inválido.'},400);const updated=nowIso();await env.DB.prepare('INSERT INTO app_state(id,data,updated_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at').bind(JSON.stringify(body.state),updated).run();return json({ok:true,updatedAt:updated});}
  catch(e){return json({error:'No se pudo guardar la base de datos.'},500)}
}
