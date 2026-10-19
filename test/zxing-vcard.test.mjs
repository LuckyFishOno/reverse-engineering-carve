import test from 'node:test';import assert from 'node:assert/strict';import {contactVCard} from '../examples/android/zxing-vcard.mjs';
test('recorded payload boundaries retain Java trim/CR behavior, cap name/address and deduplicate before escaping',()=>{
 const contact={names:[null,'\u0000 \t',' \u00a0Name\ufeff ','Ignored'],addresses:[' 1;Street ','Ignored'],phones:['a\nb','ab','a\nb'],organization:' A,B ',note:'x\r\ny'};
 assert.equal(contactVCard(contact),'BEGIN:VCARD\nVERSION:3.0\nN:\u00a0Name\ufeff\nORG:A\\,B\nADR:1\\;Street\nTEL:ab\nTEL:ab\nNOTE:x\ry\nEND:VCARD\n');
 assert.equal(contactVCard({}),'BEGIN:VCARD\nVERSION:3.0\nEND:VCARD\n');
});
test('payload rejects behavior outside its documented independent domain',()=>{
 for(const value of [null,[],{phoneTypes:[]},{unknown:1},{names:[3]},{note:'\ud800'},{note:'x'.repeat(8193)},{phones:Array(129).fill('x')},{names:['x'.repeat(8192)],organization:'x'.repeat(8192),addresses:['x'.repeat(8192)],note:'x'.repeat(8192),urls:['x']}])assert.throws(()=>contactVCard(value));
});
