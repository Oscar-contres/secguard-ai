'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { sanitizeText, redactSecrets } = require('./sanitize');

test('rechaza entradas que no son texto', () => {
  assert.equal(sanitizeText(42, 100).ok, false);
  assert.equal(sanitizeText(['a'], 100).ok, false);
  assert.equal(sanitizeText(undefined, 100).ok, false);
});

test('rechaza consultas vacías o solo con espacios', () => {
  assert.equal(sanitizeText('   \n\t  ', 100).ok, false);
});

test('rechaza consultas demasiado largas', () => {
  const r = sanitizeText('a'.repeat(101), 100);
  assert.equal(r.ok, false);
  assert.match(r.error, /100 caracteres/);
});

test('quita caracteres de control e invisibles', () => {
  const r = sanitizeText('hola\u0000‮mundo', 100);
  assert.equal(r.ok, true);
  assert.equal(r.text, 'holamundo');
});

test('conserva saltos de línea y tabulaciones internas', () => {
  const r = sanitizeText('línea 1\n\tlínea 2', 100);
  assert.equal(r.ok, true);
  assert.equal(r.text, 'línea 1\n\tlínea 2');
});

test('redacta claves y credenciales sin devolver sus valores', () => {
  const input = 'password = "hunter2abc" y sk-abcdefghijklmnopqrstuvwxyz123';
  const r = redactSecrets(input);
  assert.ok(!r.text.includes('hunter2abc'));
  assert.ok(!r.text.includes('sk-abcdefghijklmnopqrstuvwxyz123'));
  assert.equal(r.types.length, 2);
  assert.ok(r.text.includes('[REDACTADO: clave tipo sk-'));
});

test('no altera un texto sin secretos', () => {
  const input = 'Revisa esta función: const x = suma(1, 2);';
  const r = redactSecrets(input);
  assert.equal(r.text, input);
  assert.deepEqual(r.types, [
    
  ]);
});
