[README.md](https://github.com/user-attachments/files/32012018/README.md)
# Copa Davis 2026

Aplicación estática + Cloudflare Pages Functions + D1.

Estructura importante:
- functions/api/auth/index.js -> /api/auth
- functions/api/state.js -> /api/state
- functions/api/pin.js -> /api/pin
- functions/api/_utils.js -> utilidades compartidas

El PIN puede mantenerse en D1. `ADMIN_PIN` en Cloudflare funciona como PIN de bootstrap/recuperación y sincroniza el PIN almacenado en D1 cuando coincide.
