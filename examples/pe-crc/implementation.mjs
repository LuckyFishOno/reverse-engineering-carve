// Reviewed CrcUpdateT1 recurrence; the caller supplies all 256 table entries.
const uint32 = value => Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
export function crcUpdate(state,bytes,table) {
  if (!uint32(state) || !Array.isArray(bytes) || bytes.length>4096 || Array.from(bytes).some(v=>!Number.isInteger(v)||v<0||v>255)) throw new RangeError('uint32 state and at most4096bytes required');
  if (!Array.isArray(table) || table.length!==256 || Array.from(table).some(v=>!uint32(v))) throw new RangeError('Exactly256uint32table entries required');
  for (const byte of bytes) state=((state>>>8)^table[(state^byte)&255])>>>0;
  return state;
}
