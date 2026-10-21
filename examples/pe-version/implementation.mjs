// Reviewed against six captured exports of the pinned third-party Windows DLL.
const values = Object.freeze({major:16,minor:2,build:0,version:'16.02',date:'2016-05-21',copyright:'Igor Pavlov : Public domain'});
export function versionInfo(field) {
  if (typeof field !== 'string' || !Object.hasOwn(values,field)) throw new RangeError('Unknown version field');
  return values[field];
}
