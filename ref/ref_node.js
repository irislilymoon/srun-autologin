// Reference implementation: runs the portal's OWN javascript (md5, sha1 and the
// custom-alphabet base64 plugin, plus the portal's xEncode helpers) to produce
// the authentication parameters, so we have a byte-exact ground truth to
// compare a clean re-implementation against.
//
// usage: node ref_node.js <username> <password> <challenge> <ip> <ac_id>
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const here = __dirname;
const allSrc = fs.readFileSync(path.join(here, 'all.js'), 'utf8');
const portalSrc = fs.readFileSync(path.join(here, 'portal.js'), 'utf8');

// --- 1. slice only the crypto helpers out of the vendor bundle. Pulling in the
//        whole bundle would drag in jQuery, which needs a real DOM.
const iMd5 = allSrc.indexOf('//md5 v2.10.0');
const iSha1 = allSrc.indexOf('//js-sha1 v0.6.0');
const iJson2 = allSrc.indexOf('//json2');
const iB64 = allSrc.indexOf('//jquery-base64 v1.0');
const iB64End = allSrc.indexOf('// layer-v3.0.3');
if ([iMd5, iSha1, iJson2, iB64, iB64End].some((i) => i < 0)) throw new Error('bundle layout changed');

const md5Src = allSrc.slice(iMd5, iSha1);
const sha1Src = allSrc.slice(iSha1, iJson2);
const b64Src = allSrc.slice(iB64, iB64End);

// --- 2. run them in a bare sandbox (no DOM needed for these three).
function jQuery() {}
const sandbox = {
  jQuery,
  JSON,
  Math,
  Date,
  console,
  window: { navigator: { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' } },
  navigator: { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
  MobileDetect: function () {
    return { mobile: function () { return false; }, os: function () { return 'Windows'; } };
  },
};
sandbox.self = sandbox;
vm.createContext(sandbox);
vm.runInContext(md5Src, sandbox, { filename: 'md5.js' });
vm.runInContext(sha1Src, sandbox, { filename: 'sha1.js' });
vm.runInContext(b64Src, sandbox, { filename: 'base64.js' });
sandbox.$ = jQuery;

if (typeof sandbox.md5 !== 'function') throw new Error('md5 not exported');
const sha1 = sandbox.sha1 || (sandbox.window && sandbox.window.sha1);
if (typeof sha1 !== 'function') throw new Error('sha1 not exported');
sandbox.sha1 = sha1;
if (!jQuery.base64 || typeof jQuery.base64.encode !== 'function') {
  throw new Error('jQuery.base64 not available, keys=' + Object.keys(jQuery.base64 || {}));
}

// --- 3. pull the auth helpers (xEncode / s / l / json / info / pwd / chksum)
//        out of portal.js verbatim, from `var enc = ...` up to $.Login.
const start = portalSrc.indexOf('var enc = "s" + "run" + "_bx1"');
const end = portalSrc.indexOf('$.Login = function');
if (start < 0 || end < 0 || end <= start) throw new Error('could not locate auth helpers in portal.js');
vm.runInContext(portalSrc.slice(start, end), sandbox, { filename: 'portal-helpers.js' });

const infoFn = sandbox.info;
const pwdFn = sandbox.pwd;
const chksumFn = sandbox.chksum;
const xEncodeFn = sandbox.xEncode;
for (const [name, fn] of Object.entries({ info: infoFn, pwd: pwdFn, chksum: chksumFn, xEncode: xEncodeFn })) {
  if (typeof fn !== 'function') throw new Error(name + '() not exposed');
}

const [username, password, challenge, ip, ac_id] = process.argv.slice(2);

// --- 4. reproduce $.Login's parameter construction
const n = 200, type = 1;

const info = infoFn({ username, password, ip, acid: ac_id, enc_ver: 'srun_bx1' }, challenge);
const hmd5 = pwdFn(password, challenge);

let chkstr = challenge + username;
chkstr += challenge + hmd5;
chkstr += challenge + ac_id;
chkstr += challenge + ip;
chkstr += challenge + n;
chkstr += challenge + type;
chkstr += challenge + info;

process.stdout.write(JSON.stringify({
  username,
  password: '{MD5}' + hmd5,
  hmd5,
  ip,
  ac_id,
  chksum: chksumFn(chkstr),
  info,
  raw_info_plain: xEncodeFn(JSON.stringify({
    username, password, ip, acid: ac_id, enc_ver: 'srun_bx1',
  }), challenge),
  n,
  type,
  os: 'Windows 10',
  name: 'PC',
  double_stack: 0,
  _chkstr: chkstr,
}, null, 2) + '\n');
