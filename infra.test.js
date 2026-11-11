'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { scanInfrastructure } = require('./infra.js');
const T = require('./security.js');

const titles = (findings) => findings.map((f) => f.title);
const has = (findings, fragment) => findings.some((f) => f.title.includes(fragment));

test('Dockerfile inseguro: root, imagen sin versión, ADD remoto, SSH y secreto en ENV', () => {
  const df = [
    'FROM ubuntu',
    'ENV DB_PASSWORD=supersecreto',
    'ADD https://ejemplo.com/app.tar.gz /app',
    'EXPOSE 22 8080',
    'CMD ["./app"]'
  ].join('\n');
  const f = scanInfrastructure(df, 'dockerfile');
  assert.ok(has(f, 'corre como root'));
  assert.ok(has(f, 'sin versión fija'));
  assert.ok(has(f, 'ADD descarga'));
  assert.ok(has(f, 'Expone SSH'));
  assert.ok(has(f, 'Secreto definido'));
});

test('Dockerfile seguro no genera alertas de root ni de imagen sin versión', () => {
  const df = [
    'FROM node:20-alpine',
    'COPY . /app',
    'USER node',
    'HEALTHCHECK CMD wget -qO- http://localhost:8080/ || exit 1',
    'CMD ["node", "server.js"]'
  ].join('\n');
  const f = scanInfrastructure(df, 'dockerfile');
  assert.equal(has(f, 'corre como root'), false);
  assert.equal(has(f, 'sin versión fija'), false);
  assert.equal(f.some((x) => x.severity === 'high'), false);
});

test('Dockerfile con curl | sh se marca como alto riesgo', () => {
  const f = scanInfrastructure('FROM node:20\nRUN curl -fsSL https://ejemplo.com/install.sh | sh\nUSER node', 'dockerfile');
  assert.ok(f.some((x) => x.severity === 'high' && x.title.includes('curl | sh')));
});

test('nginx: detecta server_tokens, autoindex, TLS antiguo y cabeceras faltantes', () => {
  const conf = [
    'server {',
    '  listen 443 ssl;',
    '  server_tokens on;',
    '  autoindex on;',
    '  ssl_protocols TLSv1 TLSv1.2;',
    '}'
  ].join('\n');
  const f = scanInfrastructure(conf, 'nginx');
  assert.ok(has(f, 'server_tokens'));
  assert.ok(has(f, 'autoindex'));
  assert.ok(has(f, 'TLS antiguo'));
  assert.ok(has(f, 'Falta add_header Strict-Transport-Security'));
});

test('nginx: TLSv1.2 y TLSv1.3 no se marcan como protocolo antiguo', () => {
  const f = scanInfrastructure('ssl_protocols TLSv1.2 TLSv1.3;', 'nginx');
  assert.equal(has(f, 'TLS antiguo'), false);
});

test('nginx: con las cabeceras declaradas no pide cabeceras', () => {
  const conf = [
    'server {',
    '  add_header Strict-Transport-Security "max-age=31536000" always;',
    '  add_header Content-Security-Policy "default-src \'self\'";',
    '  add_header X-Frame-Options DENY;',
    '  add_header X-Content-Type-Options nosniff;',
    '  add_header Referrer-Policy no-referrer;',
    '}'
  ].join('\n');
  const f = scanInfrastructure(conf, 'nginx');
  assert.equal(has(f, 'Falta add_header'), false);
});

test('tipos sin reglas de infraestructura devuelven lista vacía', () => {
  assert.deepEqual(scanInfrastructure('X=1', 'env'), []);
});

test('quickCodeScan con reglas de .env: DEBUG y contraseña trivial', () => {
  const f = T.quickCodeScan('DEBUG=true\nDB_PASSWORD=admin\n', 'env');
  assert.ok(has(f, 'DEBUG activado'));
  assert.ok(has(f, 'Contraseña por defecto'));
});

test('quickCodeScan detecta el inicio de una clave privada en el código', () => {
  const f = T.quickCodeScan('const k = `\n-----BEGIN RSA PRIVATE KEY-----\nMIIE`', 'javascript');
  assert.ok(titles(f).some((t) => t.includes('clave privada')));
});
