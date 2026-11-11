'use strict';

// Validación del texto y redacción de secretos para el servidor.
// La redacción reutiliza las reglas de security.js, así no hay dos listas que mantener.
const T = require('./security.js');

// Caracteres de control, salvo tabulador, salto de línea y retorno de carro.
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

// Caracteres invisibles o de direccionalidad que sirven para ocultar texto a la vista.
const INVISIBLE_CHARS = /[​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;

/**
 * Valida que la consulta sea texto limpio y de tamaño razonable.
 * No cambia el significado del contenido: solo quita caracteres invisibles y de control.
 */
function sanitizeText(input, maxChars) {
  if (typeof input !== 'string') {
    return { ok: false, error: 'El campo "message" debe ser texto.' };
  }

  const text = input
    .normalize('NFC')
    .replace(INVISIBLE_CHARS, '')
    .replace(CONTROL_CHARS, '')
    .trim();

  if (!text) {
    return { ok: false, error: 'La consulta está vacía.' };
  }
  if (text.length > maxChars) {
    return { ok: false, error: `La consulta supera ${maxChars} caracteres.` };
  }
  return { ok: true, text };
}

/**
 * Sustituye credenciales por marcadores antes de enviar el texto a la IA.
 * Devuelve el texto redactado y los tipos encontrados (nunca el valor).
 */
function redactSecrets(text) {
  const types = T.findSecrets(text).map((f) => f.type);
  return { text: T.redactSecrets(text), types };
}

module.exports = { sanitizeText, redactSecrets };
