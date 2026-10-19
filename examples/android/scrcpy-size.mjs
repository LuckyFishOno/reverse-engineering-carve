// SPDX-License-Identifier: Apache-2.0
// See LICENSE.scrcpy for the upstream license and project attribution below.
// Agent reimplementation from scrcpy v5.0.1 released DEX analysis.
// Input project: https://github.com/Genymobile/scrcpy (Apache-2.0).
// Selected boundary: Size.constrain(constraints, preserveAspect) with null encoder capabilities.
export function constrainVideoSize(width, height, maxSize, alignment, preserveAspect) {
  for (const value of [width, height, alignment]) {
    if (!Number.isInteger(value) || value < 1 || value > 2147483647) throw new RangeError('Positive int32 dimensions/alignment required.');
  }
  if (!Number.isInteger(maxSize) || maxSize < -2147483648 || maxSize > 2147483647) throw new RangeError('Signed int32 maxSize required.');
  if (typeof preserveAspect !== 'boolean') throw new TypeError('preserveAspect must be boolean.');
  let resultWidth = width;
  let resultHeight = height;
  if (maxSize > 0 && (width > maxSize || height > maxSize)) {
    if (preserveAspect) {
      if (width > height) {
        resultWidth = maxSize;
        resultHeight = Math.trunc(Math.imul(height, maxSize) / width);
      } else {
        resultWidth = Math.trunc(Math.imul(width, maxSize) / height);
        resultHeight = maxSize;
      }
    } else {
      resultWidth = Math.min(width, maxSize);
      resultHeight = Math.min(height, maxSize);
    }
  }
  return [Math.max(Math.imul(Math.trunc(resultWidth / alignment), alignment), alignment),
    Math.max(Math.imul(Math.trunc(resultHeight / alignment), alignment), alignment)];
}
