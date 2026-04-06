export function titleCaseNome(nome) {
  return (nome || '')
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .map(w => w[0].toUpperCase() + w.slice(1))
    .join(' ');
}

export function normalizarEmail(email) {
  return (email || '').trim().toLowerCase();
}

export function somenteNumeros(v) {
  return (v || '').toString().replace(/\D+/g, '');
}
