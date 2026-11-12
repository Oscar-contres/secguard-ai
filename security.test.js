'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const T = require('./security.js');

const has = (findings, fragment) => findings.some((f) => f.title.includes(fragment));
const sev = (findings, fragment) => {
  const f = findings.find((x) => x.title.includes(fragment));
  return f ? f.severity : null;
};

test('JavaScript: SQL armado con "+" con datos de la petición se marca como alto', () => {
  const code = 'const userId = req.query.id;\nconst query = "SELECT * FROM users WHERE id = " + userId;';
  const f = T.quickCodeScan(code, 'javascript');
  assert.ok(has(f, 'Consulta SQL armada con "+"'));
  assert.equal(sev(f, 'Consulta SQL armada con "+"'), 'high');
  assert.equal(f[0].line, 2);
});

test('JavaScript: SQL con ${} en plantilla se marca como alto', () => {
  const code = 'db.query(`SELECT * FROM users WHERE id = ${userId}`);';
  const f = T.quickCodeScan(code, 'javascript');
  assert.ok(has(f, 'datos insertados en una plantilla'));
});

test('JavaScript: lectura de archivo con datos de la petición se marca como alto', () => {
  const code = "const data = fs.readFileSync(req.query.file, 'utf8');";
  const f = T.quickCodeScan(code, 'javascript');
  assert.equal(sev(f, 'datos de la petición'), 'high');
});

test('JavaScript: lectura de archivo con ruta variable se marca como medio', () => {
  const code = "const filePath = req.query.file;\nconst data = fs.readFileSync(filePath, 'utf8');";
  const f = T.quickCodeScan(code, 'javascript');
  assert.equal(sev(f, 'ruta variable'), 'medium');
  assert.equal(has(f, 'datos de la petición'), false);
});

test('JavaScript: fragmento del video (SQL + lectura de archivo) produce hallazgos', () => {
  const code = [
    "const mysql = require('mysql2');",
    "const fs = require('fs');",
    '',
    'function handleUserProfile(req, res) {',
    '  // Simulación de entrada vulnerable a inyección SQL',
    '  const userId = req.query.id;',
    '  const query = "SELECT * FROM users WHERE id = " + userId;',
    '  const filePath = req.query.file;',
    "  const fileContent = fs.readFileSync(filePath, 'utf8');",
    '  res.send(fileContent);',
    '}'
  ].join('\n');
  const f = T.quickCodeScan(code, 'javascript');
  assert.ok(f.length >= 2);
  assert.ok(T.riskScore(f) >= 28);
});

test('JavaScript: código normal no genera falsos positivos de SQL ni de archivos', () => {
  const code = [
    'const label = "Selecciona una opción: " + name;',
    "const config = fs.readFileSync('./config.json', 'utf8');",
    'const total = "Total: " + amount;'
  ].join('\n');
  const f = T.quickCodeScan(code, 'javascript');
  assert.equal(f.length, 0);
});

test('looksLikeHeaders acepta cabeceras copiadas de las herramientas de desarrollador', () => {
  const raw = [
    'Strict-Transport-Security: max-age=31536000',
    'Content-Type: text/html; charset=utf-8',
    'X-Frame-Options: DENY'
  ].join('\n');
  assert.equal(T.looksLikeHeaders(raw), true);
});

test('looksLikeHeaders rechaza código JavaScript pegado como cabeceras', () => {
  const code = [
    'const mysql = require("mysql2");',
    'function handleUserProfile(req, res) {',
    '  const userId = req.query.id;',
    '  res.send(userId);',
    '}'
  ].join('\n');
  assert.equal(T.looksLikeHeaders(code), false);
});

test('looksLikeHeaders rechaza texto vacío', () => {
  assert.equal(T.looksLikeHeaders(''), false);
  assert.equal(T.looksLikeHeaders('   \n  '), false);
});
