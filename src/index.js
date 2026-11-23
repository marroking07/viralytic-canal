// Viralytic AI · edición Canal
// Una app para tener un canal de videos cortos que se hace solo: tú dices de qué es tu canal,
// la IA escribe los guiones, el robot arma los videos y tú los descargas o compartes para subirlos.
// Requiere una llave de licencia (una por instalación).
const LICENSE_SERVER = 'https://viralytic-ai.pll-studio.workers.dev';
const TEXT_MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast';
const IMAGE_MODEL = '@cf/black-forest-labs/flux-1-schnell';
const IMG_CAP = 40;
const enc = new TextEncoder();
const now = () => Date.now();

// ---------------------------------------------------------------- archivos (Workers KV: gratis y sin tarjeta)
// Videos y personaje se guardan en KV (máximo 25 MB por archivo).
function archivos(env) {
  const kv = env.ARCHIVOS;
  return {
    async put(k, v, o) {
      await kv.put(k, v, {metadata: {type: o?.httpMetadata?.contentType || 'application/octet-stream'}});
    },
    async get(k) {
      const r = await kv.getWithMetadata(k, {type: 'stream'});
      return r && r.value ? {body: r.value, httpMetadata: {contentType: r.metadata?.type}} : null;
    },
    async head(k) {
      const r = await kv.list({prefix: k, limit: 1});
      return r.keys.some((x) => x.name === k) ? {} : null;
    },
    async delete(k) {
      await kv.delete(k);
    },
  };
}

// ---------------------------------------------------------------- utilidades
const json = (b, s = 200, h = {}) => new Response(JSON.stringify(b), {status: s, headers: {'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...h}});
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const clip = (t, n) => String(t || '').replace(/\s+/g, ' ').trim().slice(0, n);
function dayStart(tzOffsetH = -6, t = now()) {
  const o = -tzOffsetH * 3600000;
  return Math.floor((t - o) / 86400000) * 86400000 + o;
}

let schemaReady = false;
async function db(env) {
  if (!schemaReady) {
    await env.DB.batch([
      env.DB.prepare('CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT)'),
      env.DB.prepare('CREATE TABLE IF NOT EXISTS videos(id TEXT PRIMARY KEY, body TEXT, estado TEXT, creado INTEGER)'),
      env.DB.prepare('CREATE TABLE IF NOT EXISTS intentos(id TEXT PRIMARY KEY, n INTEGER)'),
    ]);
    schemaReady = true;
  }
  return env.DB;
}
async function get(env, k, dft = null) {
  const r = await (await db(env)).prepare('SELECT v FROM kv WHERE k=?').bind(k).first();
  return r ? JSON.parse(r.v) : dft;
}
async function put(env, k, v) {
  await (await db(env)).prepare('INSERT INTO kv(k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').bind(k, JSON.stringify(v)).run();
}

// ---------------------------------------------------------------- licencia
async function licencia(env, origin, tipo, extra = {}) {
  const lic = await get(env, 'licencia');
  if (!lic?.llave) return {ok: false, error: 'Falta activar la licencia.'};
  try {
    const r = await fetch(LICENSE_SERVER + '/api/lic/' + tipo, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({llave: lic.llave, sitio: lic.sitio || origin, instalacion: lic.instalacion, ...extra}),
    });
    const j = await r.json().catch(() => ({}));
    if (r.ok && j.ok) {
      lic.estado = 'activa';
      lic.revisada = now();
      lic.error = null;
      await put(env, 'licencia', lic);
      return j;
    }
    if ([403, 404, 409].includes(r.status)) {
      lic.estado = 'bloqueada';
      lic.error = j.error || 'Licencia no válida';
      await put(env, 'licencia', lic);
    }
    return {ok: false, error: j.error || 'No se pudo revisar la licencia (' + r.status + ')'};
  } catch (e) {
    return {ok: false, error: 'Sin conexión con el servidor de licencias.'};
  }
}
/** Revisa la licencia una vez al día; si el servidor no responde, aguanta hasta 3 días. */
async function licenciaVigente(env, origin) {
  const lic = await get(env, 'licencia');
  if (!lic?.llave) return {ok: false, error: 'Falta activar la licencia.'};
  if (lic.estado === 'activa' && now() - (lic.revisada || 0) < 86400000) return {ok: true};
  const r = await licencia(env, origin, 'revisar');
  if (r.ok) return {ok: true};
  if (lic.estado === 'activa' && now() - (lic.revisada || 0) < 3 * 86400000 && /conexión/.test(r.error)) return {ok: true};
  return r;
}

// ---------------------------------------------------------------- sesión (contraseña del dueño)
async function hashPass(pass, salt) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 100000}, key, 256);
  return b64u(bits);
}
async function hmacKey(env) {
  let s = await get(env, 'secreto');
  if (!s) {
    s = b64u(crypto.getRandomValues(new Uint8Array(32)));
    await put(env, 'secreto', s);
  }
  return crypto.subtle.importKey('raw', enc.encode(s), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign', 'verify']);
}
async function makeCookie(env) {
  const body = b64u(enc.encode(JSON.stringify({exp: now() + 30 * 86400000})));
  const sig = b64u(await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(body)));
  return `vc_sesion=${body}.${sig}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${30 * 86400}`;
}
async function loggedIn(req, env) {
  const raw = (req.headers.get('Cookie') || '').split(';').map((s) => s.trim()).find((s) => s.startsWith('vc_sesion='));
  if (!raw) return false;
  const [body, sig] = raw.slice(10).split('.');
  try {
    if (!(await crypto.subtle.verify('HMAC', await hmacKey(env), unb64u(sig), enc.encode(body)))) return false;
    return JSON.parse(new TextDecoder().decode(unb64u(body))).exp > now();
  } catch {
    return false;
  }
}
async function tooMany(env, req, key, max) {
  const ip = req.headers.get('CF-Connecting-IP') || 'x';
  const id = Math.floor(now() / 900000) + '/' + key + '/' + ip;
  const r = await (await db(env)).prepare('INSERT INTO intentos(id,n) VALUES (?,1) ON CONFLICT(id) DO UPDATE SET n=n+1 RETURNING n').bind(id).first();
  return (r?.n || 0) > max;
}

// ---------------------------------------------------------------- robot: identidad de GitHub (OIDC)
let jwks = null;
async function githubRepo(req, env) {
  const tok = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const parts = tok.split('.');
  if (parts.length !== 3) return null;
  try {
    const head = JSON.parse(new TextDecoder().decode(unb64u(parts[0])));
    const claims = JSON.parse(new TextDecoder().decode(unb64u(parts[1])));
    if (claims.iss !== 'https://token.actions.githubusercontent.com' || claims.aud !== 'viralytic-canal' || claims.exp * 1000 < now()) return null;
    if (!jwks || jwks.at < now() - 3600000) jwks = {keys: (await (await fetch('https://token.actions.githubusercontent.com/.well-known/jwks')).json()).keys, at: now()};
    const jwk = jwks.keys.find((k) => k.kid === head.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey('jwk', jwk, {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['verify']);
    if (!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, unb64u(parts[2]), enc.encode(parts[0] + '.' + parts[1])))) return null;
    const cfg = await get(env, 'robot', {});
    const repo = String(claims.repository || '').toLowerCase();
    if (!cfg.repo || cfg.repo.toLowerCase() !== repo) return null;
    if (claims.ref !== 'refs/heads/main' || String(claims.event_name || '').startsWith('pull_request')) return null;
    return repo;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- IA gratis (Cloudflare)
async function aiJSON(env, system, user, max = 2400) {
  let last;
  for (let i = 0; i < 3; i++) {
    try {
      const r = await env.AI.run(TEXT_MODEL, {messages: [{role: 'system', content: system}, {role: 'user', content: user}], max_tokens: max, temperature: 0.8});
      const t = typeof r?.response === 'string' ? r.response : JSON.stringify(r?.response || r);
      const m = t.match(/\{[\s\S]*\}/);
      if (m) return JSON.parse(m[0]);
      last = Error('respuesta sin JSON');
    } catch (e) {
      last = e;
    }
  }
  throw last;
}
async function aiImage(env, prompt) {
  const r = await env.AI.run(IMAGE_MODEL, {prompt: prompt.slice(0, 2000), steps: 4});
  const b64 = r?.image;
  if (!b64) throw Error('La IA no devolvió imagen');
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

const CANAL_DEFAULT = {nombre: '', tema: '', publico: '', idioma: 'español de México', tono: 'claro, directo y con energía', reglas: '', voz: 'es-MX-JorgeNeural', porDia: 3, color: '#2ee68c', estiloImagen: ''};
const VOCES = [
  ['es-MX-JorgeNeural', 'Jorge · hombre · México'],
  ['es-MX-DaliaNeural', 'Dalia · mujer · México'],
  ['es-US-AlonsoNeural', 'Alonso · hombre · latino'],
  ['es-US-PalomaNeural', 'Paloma · mujer · latina'],
  ['es-CO-GonzaloNeural', 'Gonzalo · hombre · Colombia'],
  ['es-CO-SalomeNeural', 'Salomé · mujer · Colombia'],
  ['es-AR-TomasNeural', 'Tomás · hombre · Argentina'],
  ['es-ES-AlvaroNeural', 'Álvaro · hombre · España'],
  ['es-ES-ElviraNeural', 'Elvira · mujer · España'],
  ['en-US-GuyNeural', 'Guy · man · English (US)'],
  ['en-US-JennyNeural', 'Jenny · woman · English (US)'],
  ['pt-BR-AntonioNeural', 'Antonio · homem · Português'],
];
const hexRgb = (h) => {
  const m = String(h || '').match(/^#?([0-9a-f]{6})$/i);
  if (!m) return [46, 230, 140];
  const n = parseInt(m[1], 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
};
function cleanCanal(d, p = CANAL_DEFAULT) {
  const n = Number(d.porDia);
  return {
    nombre: d.nombre === undefined ? p.nombre : clip(d.nombre, 60),
    tema: d.tema === undefined ? p.tema : clip(d.tema, 300),
    publico: d.publico === undefined ? p.publico : clip(d.publico, 160),
    idioma: d.idioma === undefined ? p.idioma : clip(d.idioma, 40),
    tono: d.tono === undefined ? p.tono : clip(d.tono, 120),
    reglas: d.reglas === undefined ? p.reglas : clip(d.reglas, 600),
    voz: VOCES.some((v) => v[0] === d.voz) ? d.voz : p.voz,
    porDia: Number.isFinite(n) ? Math.max(0, Math.min(10, Math.round(n))) : p.porDia,
    color: /^#[0-9a-f]{6}$/i.test(d.color || '') ? d.color : p.color,
    estiloImagen: d.estiloImagen === undefined ? p.estiloImagen : clip(d.estiloImagen, 200),
  };
}

async function listVideos(env, limit = 60) {
  const r = await (await db(env)).prepare('SELECT body FROM videos ORDER BY creado DESC LIMIT ?').bind(limit).all();
  return r.results.map((x) => JSON.parse(x.body));
}
async function saveVideo(env, v) {
  await (await db(env)).prepare('INSERT INTO videos(id,body,estado,creado) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body,estado=excluded.estado')
    .bind(v.id, JSON.stringify(v), v.estado, v.creado)
    .run();
}
async function loadVideo(env, id) {
  const r = await (await db(env)).prepare('SELECT body FROM videos WHERE id=?').bind(String(id || '')).first();
  return r ? JSON.parse(r.body) : null;
}
async function resumen(env) {
  const canal = await get(env, 'canal', CANAL_DEFAULT);
  const st = await get(env, 'estado', {});
  const start = dayStart();
  const r = await (await db(env)).prepare("SELECT COUNT(*) AS hoy FROM videos WHERE creado>=? AND estado!='error' AND estado!='borrado'").bind(start).first();
  const p = await (await db(env)).prepare("SELECT COUNT(*) AS n FROM videos WHERE estado='listo'").first();
  const g = await (await db(env)).prepare("SELECT COUNT(*) AS n FROM videos WHERE estado='haciendo'").first();
  return {hoy: r?.hoy || 0, listos: p?.n || 0, haciendo: g?.n || 0, porDia: canal.porDia, extra: st.extra || 0, ultimo: st.ultimo || null, ultimoTexto: st.ultimoTexto || ''};
}
async function necesita(env) {
  const canal = await get(env, 'canal', CANAL_DEFAULT);
  const st = await get(env, 'estado', {});
  const s = await resumen(env);
  if (!canal.tema) return {n: 0, razon: 'Falta decir de qué es tu canal.'};
  if (s.listos >= 30) return {n: 0, razon: 'Tienes 30 videos sin descargar. Descarga o borra algunos.'};
  const n = Math.max(0, canal.porDia - s.hoy) + (st.extra || 0);
  return {n, razon: n ? '' : 'Ya están los videos de hoy.'};
}
async function anotar(env, texto, patch = {}) {
  const st = await get(env, 'estado', {});
  Object.assign(st, patch, {ultimo: now(), ultimoTexto: clip(texto, 300)});
  await put(env, 'estado', st);
}

// ---------------------------------------------------------------- guion nuevo
async function nuevoVideo(env, origin) {
  const canal = await get(env, 'canal', CANAL_DEFAULT);
  const cer = await licencia(env, origin, 'cerebro', {canal});
  if (!cer.ok) throw Error(cer.error);
  const prev = (await listVideos(env, 40)).map((v) => v.titulo).filter(Boolean);
  const user = [`Escribe un guion nuevo.`, prev.length ? `NO repitas estos títulos ni sus ideas: ${prev.join(' | ')}` : ''].filter(Boolean).join('\n');
  let g = await aiJSON(env, cer.system, user);
  const words = (x) => (Array.isArray(x?.scenes) ? x.scenes : []).reduce((n, s) => n + String(s?.text || '').split(/\s+/).filter(Boolean).length, 0);
  if (words(g) < 120 && Array.isArray(g.scenes) && g.scenes.length) {
    try {
      const ex = await aiJSON(env, cer.expand, `Título: ${clip(g.title, 90)}\nEscenas (${g.scenes.length}):\n` + g.scenes.map((s, i) => `${i + 1}. ${clip(s?.text, 300)}`).join('\n'));
      if (Array.isArray(ex?.scenes) && ex.scenes.length === g.scenes.length && words(ex) > words(g)) {
        g.scenes = g.scenes.map((s, i) => ({...s, text: ex.scenes[i]?.text || s.text}));
        if (ex.title && String(ex.title).length > 15) g.title = ex.title;
      }
    } catch {}
  }
  const scenes = (Array.isArray(g.scenes) ? g.scenes : [])
    .map((s) => ({text: clip(s.text, 420), card: clip(s.card, 40).toUpperCase(), visualPrompt: clip(s.visual, 300)}))
    .filter((s) => s.text.length > 8)
    .slice(0, 8);
  if (scenes.length < 4) throw Error('La IA hizo un guion muy corto; se intenta en la siguiente vuelta.');
  const tags = (Array.isArray(g.tags) ? g.tags : String(g.tags || '').split(/[,\s]+/)).map((t) => '#' + String(t).replace(/^#+/, '').replace(/[^\p{L}\p{N}_]/gu, '')).filter((t) => t.length > 2).slice(0, 5);
  const v = {
    id: crypto.randomUUID(),
    estado: 'haciendo',
    creado: now(),
    token: crypto.randomUUID(),
    titulo: clip(g.title, 90) || clip(scenes[0].text, 80),
    descripcion: [clip(g.description, 400), '', [...new Set(['#Shorts', ...tags])].join(' ')].join('\n'),
    scenes,
    imgStyle: cer.imgStyle,
  };
  await saveVideo(env, v);
  return v;
}

// ---------------------------------------------------------------- API
async function api(req, env, path, origin) {
  const method = req.method;
  const body = method === 'POST' && !path.startsWith('robot/video') ? await req.json().catch(() => ({})) : {};

  // --- Robot (GitHub Actions del dueño) ---
  if (path.startsWith('robot/')) {
    const repo = await githubRepo(req, env);
    if (!repo) return json({error: 'Robot no autorizado'}, 401);
    await put(env, 'robotVisto', now());
    const lic = await licenciaVigente(env, origin);
    if (!lic.ok) return json({error: lic.error}, 403);
    if (path === 'robot/revisar') return json({work: (await necesita(env)).n > 0});
    if (path === 'robot/codigo') {
      const r = await licencia(env, origin, 'robot');
      if (!r.ok) return json({error: r.error}, 403);
      return new Response(r.codigo, {headers: {'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store'}});
    }
    if (path === 'robot/siguiente') {
      const need = await necesita(env);
      if (!need.n) {
        await anotar(env, need.razon);
        return json({action: 'idle', reason: need.razon});
      }
      try {
        const v = await nuevoVideo(env, origin);
        const st = await get(env, 'estado', {});
        const s = await resumen(env);
        const canal = await get(env, 'canal', CANAL_DEFAULT);
        if ((st.extra || 0) > 0 && s.hoy > canal.porDia) st.extra -= 1;
        await put(env, 'estado', st);
        await anotar(env, 'Guion listo: ' + v.titulo);
        return json({action: 'produce', voice: canal.voz, project: {id: v.id, renderToken: v.token, title: v.titulo, scenes: v.scenes, edgeVoice: canal.voz, marca: canal.nombre || 'Mi canal', color: hexRgb(canal.color)}});
      } catch (e) {
        await anotar(env, 'Error al escribir: ' + e.message);
        return json({error: String(e.message || e)}, 502);
      }
    }
    if (path === 'robot/imagen') {
      const v = await loadVideo(env, body.id);
      const sc = v?.scenes?.[Number(body.index)];
      if (!sc) return json({error: 'Escena inválida'}, 400);
      const st = await get(env, 'estado', {});
      const d = dayStart();
      if (st.imgDia !== d) Object.assign(st, {imgDia: d, imgN: 0});
      if ((st.imgN || 0) >= IMG_CAP) return json({error: 'Tope diario de imágenes'}, 429);
      st.imgN = (st.imgN || 0) + 1;
      await put(env, 'estado', st);
      try {
        const img = await aiImage(env, (sc.visualPrompt || sc.card + ': ' + sc.text) + '.' + (v.imgStyle || ''));
        return new Response(img, {headers: {'Content-Type': 'image/jpeg'}});
      } catch (e) {
        return json({error: String(e.message || e).slice(0, 200)}, 502);
      }
    }
    if (path.startsWith('robot/personaje/')) {
      const k = path.slice(16);
      const o = await archivos(env).get('personaje/' + (k === 'open' ? 'abierta' : 'cerrada'));
      if (!o) return json({error: 'Sin imagen'}, 404);
      return new Response(o.body, {headers: {'Content-Type': o.httpMetadata?.contentType || 'image/png'}});
    }
    if (path === 'robot/video') {
      const v = await loadVideo(env, req.headers.get('X-Project-Id'));
      if (!v || v.token !== req.headers.get('X-Render-Token')) return json({error: 'Video desconocido'}, 404);
      const bytes = await req.arrayBuffer();
      if (bytes.byteLength < 10000) return json({error: 'Video inválido'}, 400);
      if (bytes.byteLength > 25e6) return json({error: 'El video pesa más de 25 MB'}, 413);
      await archivos(env).put('videos/' + v.id + '.mp4', bytes, {httpMetadata: {contentType: 'video/mp4'}});
      v.estado = 'listo';
      v.listo = now();
      v.tam = bytes.byteLength;
      try {
        v.duraciones = JSON.parse(req.headers.get('X-Scene-Durations') || '[]');
      } catch {}
      await saveVideo(env, v);
      return json({ok: true});
    }
    if (path === 'robot/fallo') {
      const v = await loadVideo(env, body.id);
      if (v && v.estado === 'haciendo') {
        v.estado = 'error';
        v.error = clip(body.error, 300);
        await saveVideo(env, v);
      }
      await anotar(env, 'Error: ' + clip(body.error, 200));
      return json({ok: true});
    }
    return json({error: 'No existe'}, 404);
  }

  // --- Instalación inicial: llave + contraseña ---
  const pass = await get(env, 'pass');
  if (path === 'estado-publico') return json({instalada: !!pass, licencia: (await get(env, 'licencia'))?.estado || null});
  if (path === 'instalar') {
    if (pass) return json({error: 'Ya está instalada. Inicia sesión.'}, 409);
    if (await tooMany(env, req, 'instalar', 10)) return json({error: 'Demasiados intentos. Espera 15 minutos.'}, 429);
    const llave = String(body.llave || '').trim().toUpperCase();
    const p1 = String(body.password || '');
    if (p1.length < 8) return json({error: 'La contraseña debe tener al menos 8 caracteres.'}, 400);
    const inst = (await get(env, 'licencia'))?.instalacion || 'inst-' + b64u(crypto.getRandomValues(new Uint8Array(18)));
    await put(env, 'licencia', {llave, sitio: origin, instalacion: inst, estado: 'pendiente'});
    const r = await licencia(env, origin, 'activar');
    if (!r.ok) return json({error: r.error}, 403);
    const salt = b64u(crypto.getRandomValues(new Uint8Array(16)));
    await put(env, 'pass', {salt, hash: await hashPass(p1, salt)});
    return json({ok: true, cliente: r.cliente}, 200, {'Set-Cookie': await makeCookie(env)});
  }
  if (path === 'entrar') {
    if (!pass) return json({error: 'Primero instala con tu llave.'}, 409);
    if (await tooMany(env, req, 'entrar', 10)) return json({error: 'Demasiados intentos. Espera 15 minutos.'}, 429);
    if ((await hashPass(String(body.password || ''), pass.salt)) !== pass.hash) return json({error: 'Contraseña incorrecta'}, 401);
    return json({ok: true}, 200, {'Set-Cookie': await makeCookie(env)});
  }
  if (path === 'salir') return json({ok: true}, 200, {'Set-Cookie': 'vc_sesion=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax'});

  // --- Todo lo demás pide sesión ---
  if (!(await loggedIn(req, env))) return json({error: 'Inicia sesión'}, 401);
  if (method === 'POST' && req.headers.get('Origin') && req.headers.get('Origin') !== origin) return json({error: 'Origen no permitido'}, 403);
  const lic = await licenciaVigente(env, origin);

  if (path === 'todo') {
    return json({
      licencia: {ok: lic.ok, error: lic.ok ? null : lic.error},
      canal: await get(env, 'canal', CANAL_DEFAULT),
      voces: VOCES,
      robot: {...(await get(env, 'robot', {})), visto: await get(env, 'robotVisto')},
      personaje: !!(await archivos(env).head('personaje/cerrada')),
      resumen: await resumen(env),
      necesita: await necesita(env),
      videos: (await listVideos(env)).filter((v) => v.estado !== 'borrado').map(({token, scenes, imgStyle, ...v}) => ({...v, escenas: scenes?.length || 0})),
      origin,
    });
  }
  if (!lic.ok && !['robot-config', 'video-borrar'].includes(path)) return json({error: lic.error}, 403);
  if (path === 'canal') {
    const c = cleanCanal(body, await get(env, 'canal', CANAL_DEFAULT));
    await put(env, 'canal', c);
    return json({ok: true, canal: c});
  }
  if (path === 'robot-config') {
    const m = String(body.repo || '').trim().match(/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:\/|$)/i) || String(body.repo || '').trim().match(/^([\w.-]+)\/([\w.-]+)$/);
    if (!m) return json({error: 'Pega el enlace de tu repositorio de GitHub (github.com/usuario/repositorio).'}, 400);
    const repo = `${m[1]}/${m[2]}`;
    await put(env, 'robot', {repo});
    return json({ok: true, repo});
  }
  if (path === 'mas') {
    const st = await get(env, 'estado', {});
    st.extra = Math.min(20, (st.extra || 0) + Math.max(1, Math.min(10, Number(body.n) || 3)));
    await put(env, 'estado', st);
    return json({ok: true, extra: st.extra});
  }
  if (path === 'personaje-crear') {
    const d = clip(body.descripcion, 500);
    if (d.length < 10) return json({error: 'Describe a tu personaje (cómo es, ropa, estilo).'}, 400);
    try {
      const img = await aiImage(
        env,
        `Portrait from the chest up of ${d}. Friendly expression, looking at the camera, centered, head and shoulders, 3D animated movie character style. ` +
          'Plain solid bright green background (chroma key green #00B140), even lighting, no shadows on the background. No text.',
      );
      await archivos(env).put('personaje/cerrada', img, {httpMetadata: {contentType: 'image/jpeg'}});
      await archivos(env).delete('personaje/abierta');
      return json({ok: true});
    } catch (e) {
      return json({error: 'No se pudo dibujar: ' + e.message}, 502);
    }
  }
  if (path === 'personaje-subir') {
    // Imagen propia en base64 (fondo verde liso recomendado). Opcional: la versión con boca abierta.
    for (const [k, campo] of [['cerrada', 'cerrada'], ['abierta', 'abierta']]) {
      const s = String(body[campo] || '');
      if (!s) continue;
      const m = s.match(/^data:(image\/(png|jpeg|webp));base64,(.+)$/);
      if (!m) return json({error: 'Imagen inválida'}, 400);
      const bytes = Uint8Array.from(atob(m[3]), (c) => c.charCodeAt(0));
      if (bytes.length > 6e6) return json({error: 'La imagen pesa más de 6 MB'}, 400);
      await archivos(env).put('personaje/' + k, bytes, {httpMetadata: {contentType: m[1]}});
    }
    if (!body.abierta) await archivos(env).delete('personaje/abierta');
    return json({ok: true});
  }
  if (path === 'video-borrar') {
    const v = await loadVideo(env, body.id);
    if (!v) return json({error: 'No existe'}, 404);
    await archivos(env).delete('videos/' + v.id + '.mp4');
    v.estado = 'borrado';
    await saveVideo(env, v);
    return json({ok: true});
  }
  if (path === 'video-subido') {
    const v = await loadVideo(env, body.id);
    if (!v) return json({error: 'No existe'}, 404);
    v.subido = !!body.subido;
    await saveVideo(env, v);
    return json({ok: true});
  }
  return json({error: 'No existe'}, 404);
}

// ---------------------------------------------------------------- Worker
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const origin = url.origin;
    try {
      if (url.pathname.startsWith('/api/')) return await api(req, env, url.pathname.slice(5), origin);
      if (url.pathname.startsWith('/archivo/')) {
        if (!(await loggedIn(req, env))) return new Response('Inicia sesión', {status: 401});
        const [kind, id] = url.pathname.slice(9).split('/');
        const key = kind === 'personaje' ? 'personaje/cerrada' : kind === 'video' ? 'videos/' + String(id || '').replace(/[^a-f0-9-]/g, '') + '.mp4' : '';
        const o = key && (await archivos(env).get(key));
        if (!o) return new Response('No existe', {status: 404});
        const h = {'Content-Type': o.httpMetadata?.contentType || 'application/octet-stream', 'Cache-Control': 'private, max-age=300'};
        if (kind === 'video' && url.searchParams.has('descargar')) h['Content-Disposition'] = `attachment; filename="video-${String(id).slice(0, 8)}.mp4"`;
        return new Response(o.body, {headers: h});
      }
      return new Response(PAGE, {headers: {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY'}});
    } catch (e) {
      return json({error: 'Error interno: ' + String(e?.message || e).slice(0, 200)}, 500);
    }
  },
};

// ---------------------------------------------------------------- Pantalla (celular primero)
const PAGE = `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Mi canal · Viralytic AI</title><meta name="theme-color" content="#0b1015">
<style>
:root{--bg:#0b1015;--card:#131b22;--line:#223039;--txt:#e9f1f5;--mut:#8ea2ad;--acc:#2ee68c;--bad:#ff6b6b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:16px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:720px;margin:0 auto;padding:16px 16px 96px}h1{font-size:22px;margin:8px 0 4px}h2{font-size:18px;margin:0 0 10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;margin:12px 0}
.mut{color:var(--mut);font-size:14px}label{display:block;margin:10px 0 4px;font-size:14px;color:var(--mut)}
input,select,textarea{width:100%;padding:12px;border-radius:12px;border:1px solid var(--line);background:#0e151b;color:var(--txt);font:inherit}
textarea{min-height:84px}.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:12px 16px;border-radius:12px;border:1px solid var(--line);background:#18232c;color:var(--txt);font:inherit;font-weight:600;cursor:pointer;text-decoration:none}
.btn.p{background:var(--acc);color:#06100b;border-color:var(--acc)}.btn:disabled{opacity:.5}.row{display:flex;gap:8px;flex-wrap:wrap}.row>*{flex:1 1 auto}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.stats div{background:#0e151b;border-radius:12px;padding:10px;text-align:center}.stats b{display:block;font-size:22px}
nav{position:fixed;bottom:0;left:0;right:0;background:#0e151bf2;border-top:1px solid var(--line);display:flex;justify-content:space-around;padding:8px 4px calc(8px + env(safe-area-inset-bottom))}
nav button{background:none;border:0;color:var(--mut);font:inherit;font-size:12px;padding:6px 8px;border-radius:10px}nav button.on{color:var(--acc);background:#16222a}
.vid{display:grid;grid-template-columns:110px 1fr;gap:12px;align-items:start}.vid video{width:110px;aspect-ratio:9/16;border-radius:10px;background:#000;object-fit:cover}
.pill{display:inline-block;font-size:12px;padding:2px 8px;border-radius:99px;background:#1d2a33;color:var(--mut)}.pill.ok{background:#123824;color:var(--acc)}.pill.bad{background:#3a1717;color:var(--bad)}
.msg{padding:10px 12px;border-radius:12px;background:#13261d;color:#bff5d8;margin-top:10px}.msg.e{background:#2a1414;color:#ffc9c9}
ol li{margin:6px 0}.hide{display:none}img.av{width:160px;border-radius:14px;background:#00b140}
</style></head><body><main id="app"><p class="mut">Cargando…</p></main><nav id="nav" class="hide"></nav>
<script>
const $=s=>document.querySelector(s);const app=$('#app');let S=null,tab='videos';
const esc=t=>String(t??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function call(p,b){const r=await fetch('/api/'+p,{method:b?'POST':'GET',headers:b?{'Content-Type':'application/json'}:{},body:b?JSON.stringify(b):undefined});const j=await r.json().catch(()=>({}));if(!r.ok)throw Error(j.error||'Error');return j}
function msg(t,e){const m=document.createElement('div');m.className='msg'+(e?' e':'');m.textContent=t;app.prepend(m);scrollTo(0,0);setTimeout(()=>m.remove(),7000)}
async function inicio(){const p=await call('estado-publico');if(!p.instalada)return instalar();try{S=await call('todo');pinta()}catch(e){entrar()}}
function instalar(){$('#nav').className='hide';app.innerHTML=\`<h1>Activa tu canal</h1><p class="mut">Pon la llave que te dieron al comprar y crea tu contraseña. La llave sirve para una sola instalación.</p>
<div class="card"><label>Llave de licencia</label><input id="ll" placeholder="VRL-XXXX-XXXX-XXXX-XXXX" autocapitalize="characters">
<label>Crea tu contraseña (mínimo 8)</label><input id="p1" type="password" autocomplete="new-password"><label>Repítela</label><input id="p2" type="password" autocomplete="new-password">
<p></p><button class="btn p" id="go" style="width:100%">Activar</button></div>\`;
$('#go').onclick=async()=>{if($('#p1').value!==$('#p2').value)return msg('Las contraseñas no coinciden',1);$('#go').disabled=true;try{await call('instalar',{llave:$('#ll').value,password:$('#p1').value});inicio()}catch(e){msg(e.message,1);$('#go').disabled=false}}}
function entrar(){$('#nav').className='hide';app.innerHTML=\`<h1>Entrar</h1><div class="card"><label>Contraseña</label><input id="pw" type="password" autocomplete="current-password"><p></p><button class="btn p" id="go" style="width:100%">Entrar</button></div>\`;
$('#go').onclick=async()=>{try{await call('entrar',{password:$('#pw').value});inicio()}catch(e){msg(e.message,1)}}}
const tabs=[['videos','🎬 Videos'],['canal','✏️ Mi canal'],['personaje','🙂 Personaje'],['robot','🤖 Robot']];
function nav(){const n=$('#nav');n.className='';n.innerHTML=tabs.map(([k,t])=>\`<button class="\${tab===k?'on':''}" data-t="\${k}">\${t}</button>\`).join('');n.querySelectorAll('button').forEach(b=>b.onclick=()=>{tab=b.dataset.t;pinta()})}
function pasos(){const c=S.canal,r=S.robot;return [['Di de qué es tu canal',!!c.tema,'canal'],['Crea tu personaje',S.personaje,'personaje'],['Conecta tu robot (una sola vez)',!!r.visto,'robot']]}
function pinta(){nav();const s=S.resumen;let h='';
if(!S.licencia.ok)h+=\`<div class="msg e">⚠ \${esc(S.licencia.error)}</div>\`;
const ps=pasos();if(ps.some(p=>!p[1]))h+=\`<div class="card"><h2>Para empezar</h2><ol>\${ps.map(p=>\`<li>\${p[1]?'✅':'⬜'} <a href="#" data-go="\${p[2]}" style="color:var(--txt)">\${p[0]}</a></li>\`).join('')}</ol></div>\`;
if(tab==='videos')h+=vVideos();if(tab==='canal')h+=vCanal();if(tab==='personaje')h+=vPersonaje();if(tab==='robot')h+=vRobot();
app.innerHTML=\`<h1>\${esc(S.canal.nombre||'Mi canal')}</h1><div class="stats"><div><b>\${s.hoy}/\${s.porDia}</b><span class="mut">hoy</span></div><div><b>\${s.listos}</b><span class="mut">listos</span></div><div><b>\${s.haciendo}</b><span class="mut">haciéndose</span></div></div>\`+h;
app.querySelectorAll('[data-go]').forEach(a=>a.onclick=e=>{e.preventDefault();tab=a.dataset.go;pinta()});enlaza()}
function vVideos(){const vs=S.videos;return \`<div class="card"><div class="row"><button class="btn p" data-mas="3">⚡ 3 videos más</button><button class="btn" data-mas="5">5 más</button></div>
<p class="mut">\${S.resumen.ultimoTexto?'Robot: '+esc(S.resumen.ultimoTexto):'El robot revisa cada 3 horas y hace los videos del día.'}</p></div>\`+
(vs.length?vs.map(v=>\`<div class="card vid">\${v.estado==='listo'?\`<video src="/archivo/video/\${v.id}" preload="metadata" controls playsinline></video>\`:'<div style="width:110px;aspect-ratio:9/16;border-radius:10px;background:#0e151b"></div>'}
<div><b>\${esc(v.titulo)}</b><br>\${v.estado==='listo'?'<span class="pill ok">Listo</span>':v.estado==='error'?'<span class="pill bad">Falló</span>':'<span class="pill">Haciéndose…</span>'} \${v.subido?'<span class="pill ok">Ya lo subí</span>':''}
\${v.estado==='listo'?\`<div class="row" style="margin-top:8px"><button class="btn p" data-share="\${v.id}">Compartir</button><a class="btn" href="/archivo/video/\${v.id}?descargar">Descargar</a></div>
<div class="row" style="margin-top:8px"><button class="btn" data-copy="\${v.id}">Copiar título y texto</button><button class="btn" data-sub="\${v.id}">\${v.subido?'Marcar no subido':'Ya lo subí'}</button><button class="btn" data-del="\${v.id}">Borrar</button></div>\`:v.estado==='error'?\`<p class="mut">\${esc(v.error||'')}</p><button class="btn" data-del="\${v.id}">Quitar</button>\`:''}</div></div>\`).join(''):'<div class="card mut">Todavía no hay videos. Termina los pasos de arriba y toca "3 videos más".</div>')}
function vCanal(){const c=S.canal;return \`<div class="card"><h2>¿De qué es tu canal?</h2>
<label>Nombre del canal</label><input id="c_nombre" value="\${esc(c.nombre)}" placeholder="Ej.: Recetas Fit">
<label>Tema (sé específico)</label><textarea id="c_tema" placeholder="Ej.: recetas saludables en 10 minutos con ingredientes baratos de México">\${esc(c.tema)}</textarea>
<label>¿Para quién es?</label><input id="c_publico" value="\${esc(c.publico)}" placeholder="Ej.: mamás que trabajan">
<div class="row"><div><label>Idioma</label><input id="c_idioma" value="\${esc(c.idioma)}"></div><div><label>Videos por día</label><select id="c_porDia">\${[0,1,2,3,4,5,6,8,10].map(n=>\`<option \${n==c.porDia?'selected':''}>\${n}</option>\`).join('')}</select></div></div>
<label>Tono</label><input id="c_tono" value="\${esc(c.tono)}">
<label>Voz</label><select id="c_voz">\${S.voces.map(v=>\`<option value="\${v[0]}" \${v[0]===c.voz?'selected':''}>\${v[1]}</option>\`).join('')}</select>
<label>Color de tu marca</label><input id="c_color" type="color" value="\${esc(c.color)}" style="height:48px">
<label>Estilo de las imágenes (opcional)</label><input id="c_estiloImagen" value="\${esc(c.estiloImagen)}" placeholder="Ej.: fotos realistas de comida, luz natural">
<label>Reglas extra (opcional)</label><textarea id="c_reglas" placeholder="Ej.: no hablar de política, siempre terminar con una pregunta">\${esc(c.reglas)}</textarea>
<p></p><button class="btn p" id="gcanal" style="width:100%">Guardar</button></div>\`}
function vPersonaje(){return \`<div class="card"><h2>Tu personaje</h2>\${S.personaje?\`<img class="av" src="/archivo/personaje?\${Date.now()}">\`:'<p class="mut">Aún no tienes personaje.</p>'}
<label>Descríbelo y la IA lo dibuja</label><textarea id="pdesc" placeholder="Ej.: mujer de 30 años, cabello rizado, lentes, blusa amarilla, sonriente"></textarea>
<p></p><button class="btn p" id="pcrear" style="width:100%">Crear con IA</button>
<p class="mut" style="margin-top:14px">O sube tu propia imagen (mejor con fondo verde liso). Si subes otra con la boca abierta, se verá hablando.</p>
<label>Imagen (boca cerrada)</label><input id="pf1" type="file" accept="image/*"><label>Opcional: boca abierta</label><input id="pf2" type="file" accept="image/*">
<p></p><button class="btn" id="psubir" style="width:100%">Subir mis imágenes</button></div>\`}
function wfLink(){const r=S.robot.repo;if(!r)return '';const v=JSON.stringify({app:S.origin},null,2);return 'https://github.com/'+r+'/new/main?filename=robot.json&value='+encodeURIComponent(v)}
function vRobot(){const r=S.robot;return \`<div class="card"><h2>Robot</h2>\${r.visto?\`<p><span class="pill ok">Conectado</span> Última vez: \${new Date(r.visto).toLocaleString()}</p>\`:'<p><span class="pill">Sin conectar</span></p>'}
<ol><li>Pega aquí el enlace de tu repositorio de GitHub (el que se creó al instalar).<input id="repo" value="\${esc(r.repo||'')}" placeholder="https://github.com/tu-usuario/tu-repositorio"><p></p><button class="btn" id="grepo">Guardar</button></li>
\${r.repo?\`<li>Toca este botón: se abre GitHub con el archivo ya escrito. Solo dale <b>Commit changes</b>.<p></p><a class="btn p" href="\${wfLink()}" target="_blank" rel="noopener">Conectar robot en GitHub</a></li>
<li>En GitHub entra a <b>Actions</b> y, si te lo pide, toca <b>Enable workflows</b>. Listo: el robot trabaja solo cada 3 horas.</li>\`:''}</ol></div>\`}
function enlaza(){app.querySelectorAll('[data-mas]').forEach(b=>b.onclick=async()=>{try{await call('mas',{n:+b.dataset.mas});msg('Pedido. El robot los hace en su próxima vuelta (máx. 3 horas).');S=await call('todo');pinta()}catch(e){msg(e.message,1)}});
app.querySelectorAll('[data-share]').forEach(b=>b.onclick=()=>compartir(b.dataset.share));
app.querySelectorAll('[data-copy]').forEach(b=>b.onclick=()=>{const v=S.videos.find(x=>x.id===b.dataset.copy);navigator.clipboard.writeText(v.titulo+'\\n\\n'+v.descripcion).then(()=>msg('Copiado. Pégalo al subir el video.'),()=>msg('No se pudo copiar',1))});
app.querySelectorAll('[data-sub]').forEach(b=>b.onclick=async()=>{const v=S.videos.find(x=>x.id===b.dataset.sub);await call('video-subido',{id:v.id,subido:!v.subido});S=await call('todo');pinta()});
app.querySelectorAll('[data-del]').forEach(b=>b.onclick=async()=>{if(!confirm('¿Borrar este video?'))return;await call('video-borrar',{id:b.dataset.del});S=await call('todo');pinta()});
const g=$('#gcanal');if(g)g.onclick=async()=>{const d={};['nombre','tema','publico','idioma','porDia','tono','voz','color','estiloImagen','reglas'].forEach(k=>d[k]=$('#c_'+k).value);try{await call('canal',d);S=await call('todo');msg('Guardado.');pinta()}catch(e){msg(e.message,1)}};
const pc=$('#pcrear');if(pc)pc.onclick=async()=>{pc.disabled=true;pc.textContent='Dibujando…';try{await call('personaje-crear',{descripcion:$('#pdesc').value});S=await call('todo');pinta()}catch(e){msg(e.message,1);pc.disabled=false;pc.textContent='Crear con IA'}};
const ps=$('#psubir');if(ps)ps.onclick=async()=>{const rd=f=>f?new Promise(r=>{const x=new FileReader();x.onload=()=>r(x.result);x.readAsDataURL(f)}):null;const a=$('#pf1').files[0],b=$('#pf2').files[0];if(!a)return msg('Elige la imagen primero',1);try{await call('personaje-subir',{cerrada:await rd(a),abierta:await rd(b)});S=await call('todo');pinta()}catch(e){msg(e.message,1)}};
const gr=$('#grepo');if(gr)gr.onclick=async()=>{try{await call('robot-config',{repo:$('#repo').value});S=await call('todo');pinta()}catch(e){msg(e.message,1)}}}
async function compartir(id){const v=S.videos.find(x=>x.id===id);try{const blob=await (await fetch('/archivo/video/'+id)).blob();const f=new File([blob],'video.mp4',{type:'video/mp4'});
if(navigator.canShare&&navigator.canShare({files:[f]})){await navigator.clipboard.writeText(v.titulo+'\\n\\n'+v.descripcion).catch(()=>{});await navigator.share({files:[f],title:v.titulo,text:v.titulo});}
else{location.href='/archivo/video/'+id+'?descargar';msg('Tu celular no deja compartir directo: se descargó el video.')}}catch(e){if(e.name!=='AbortError')msg('No se pudo compartir: '+e.message,1)}}
inicio();setInterval(async()=>{if(S&&tab==='videos'&&S.resumen.haciendo){try{S=await call('todo');pinta()}catch{}}},30000);
</script></body></html>`;
