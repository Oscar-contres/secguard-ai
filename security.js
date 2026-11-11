/*
 * SecGuard AI · Herramientas defensivas locales.
 * Todas las funciones de este archivo corren en el navegador.
 * Ninguna envía datos a un servidor.
 */
(function (global) {
  'use strict';

  var COMMON_WORDS = [
    'password', 'contraseña', 'contrasena', 'qwerty', 'letmein', 'welcome',
    'admin', 'iloveyou', 'dragon', 'monkey', 'football', 'sunshine',
    '123456', '12345678', 'abc123'
  ];
  var SEQUENCES = /(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf|zxcv)/i;
  var REPEATS = /(.)\1{2,}/;

  var WEIGHTS = { high: 20, medium: 8, low: 3, ok: 0 };

  // ---------- Puntuación de riesgo ----------
  function riskScore(items) {
    var total = items.reduce(function (sum, it) {
      return sum + (WEIGHTS[it.severity] || 0);
    }, 0);
    return Math.min(100, total);
  }

  function riskLevel(score) {
    if (score < 30) return 'Bajo';
    if (score < 60) return 'Medio';
    return 'Alto';
  }

  // ---------- Contraseñas ----------
  function poolSize(pw) {
    var pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
