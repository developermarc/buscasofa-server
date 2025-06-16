const spamKeywords = ['gratis', 'haz clic', 'gana dinero', 'comparte ya', 'suscríbete', 'oferta exclusiva'];

export function isSpam(comment) {
  const lower = comment.toLowerCase();
  return spamKeywords.some(keyword => lower.includes(keyword));
}