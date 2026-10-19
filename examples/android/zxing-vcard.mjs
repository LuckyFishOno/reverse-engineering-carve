// Independent reconstruction of the bounded shipped ZXing4.7.8 payload.
// No Android, UI, QR bitmap or phone-display-formatting dependency.
export function contactVCard(contact) {
  if (contact === null || typeof contact !== 'object' || Array.isArray(contact)) throw new TypeError('Expected one contact object.');
  const keys = ['names', 'organization', 'addresses', 'phones', 'phoneTypes', 'emails', 'urls', 'note'];
  for (const key of Object.keys(contact)) if (!keys.includes(key)) throw new TypeError('Unsupported contact field: ' + key);
  if (contact.phoneTypes != null) throw new TypeError('phoneTypes must be absent or null in this payload domain.');
  let units = 0;
  const text = value => {
    if (value == null) return null;
    if (typeof value !== 'string' || !value.isWellFormed() || value.length > 8192) throw new TypeError('Fields require well-formed strings of at most8192 UTF16 units or null.');
    units += value.length; if (units > 32768) throw new RangeError('Contact text exceeds32768 UTF16 units.');
    return value;
  };
  const list = value => {
    if (value == null) return null;
    if (!Array.isArray(value) || value.length > 128) throw new TypeError('List fields require at most128 string/null items.');
    return value.map(text);
  };
  // Validate the entire supplied domain, including values after first-item caps.
  const names = list(contact.names), organization = text(contact.organization), addresses = list(contact.addresses),
    phones = list(contact.phones), emails = list(contact.emails), urls = list(contact.urls), note = text(contact.note);
  const trim = value => {
    if (value === null) return null;
    let first = 0, last = value.length;
    while (first < last && value.charCodeAt(first) <= 32) first++;
    while (last > first && value.charCodeAt(last - 1) <= 32) last--;
    return first === last ? null : value.slice(first, last);
  };
  // Exact observed behavior: escape backslash/comma/semicolon, remove LF.
  // Internal CR/control characters remain; this is not an RFC conformance fix.
  const field = value => value.replace(/([\\,;])/g, '\\$1').replace(/\n/g, '');
  let payload = 'BEGIN:VCARD\nVERSION:3.0\n';
  const append = (prefix, value) => { const t = trim(value); if (t !== null) payload += prefix + ':' + field(t) + '\n'; };
  const unique = (prefix, values, max) => {
    if (values === null) return;
    const seen = new Set(); let count = 0;
    for (const value of values) {
      const t = trim(value); if (t === null || seen.has(t)) continue;
      append(prefix, t); if (++count === max) return; seen.add(t);
    }
  };
  unique('N', names, 1); append('ORG', organization); unique('ADR', addresses, 1);
  unique('TEL', phones, 2147483647); unique('EMAIL', emails, 2147483647); unique('URL', urls, 2147483647); append('NOTE', note);
  return payload + 'END:VCARD\n';
}
