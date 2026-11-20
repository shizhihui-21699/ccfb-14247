import { startBackend, BACKEND_PORT } from './backend.ts';
import { startCache, CACHE_PORT } from './cache.ts';

await startBackend();
await startCache(BACKEND_PORT);
console.log(`origin:  http://127.0.0.1:${BACKEND_PORT}`);
console.log(`cache:   http://127.0.0.1:${CACHE_PORT}  <- scan this one`);
console.log('routes:  /index.html  /search.html  /redirect.html  /api/data.json  /static/app.js');
