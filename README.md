# Copa Davis 2026 — Versión definitiva

Proyecto preparado para publicar como sitio estático + Cloudflare Pages Functions + Cloudflare D1.

## Archivos
- `index.html`: página completa responsive. La foto real del grupo está embebida dentro del HTML y además disponible en `assets/hero.jpeg`.
- `schema.sql`: esquema inicial de D1.
- `wrangler.toml`: configuración de Cloudflare (reemplazar el ID de D1).
- `functions/api/`: endpoints para estado, PIN y autenticación.
- `assets/hero.jpeg`: foto original del grupo.

## Importante
La interfaz ya funciona como prototipo local con guardado en el navegador. Para producción hay que crear una base D1, colocar su `database_id` en `wrangler.toml`, ejecutar `schema.sql` y configurar el secreto `ADMIN_PIN`.

## Publicación recomendada
Usar **Cloudflare Pages**, no desplegarlo como un Worker independiente. El directorio raíz del proyecto es esta carpeta.
