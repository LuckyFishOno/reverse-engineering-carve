// SPDX-License-Identifier: MIT
// Agent reimplementation of jq-1.8.2 utf8bytelength for well-formed Unicode strings.
// Input project https://github.com/jqlang/jq; upstream COPYING is retained by the integration package.
export function utf8ByteLength(text) {
  if (typeof text !== 'string') throw new TypeError('A Unicode string is required.');
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit < 0x80) bytes++;
    else if (unit < 0x800) bytes += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new RangeError('Unpaired surrogate is outside the selected Unicode contract.');
      bytes += 4;
    } else {
      if (unit >= 0xdc00 && unit <= 0xdfff) throw new RangeError('Unpaired surrogate is outside the selected Unicode contract.');
      bytes += 3;
    }
  }
  return bytes;
}
