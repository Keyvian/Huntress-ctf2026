// Huntress Script Triage -- inert static-analysis fixture (wsh_jscript_windows)
function decodeBase64(text) {
  var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var clean = text.replace(/[^A-Za-z0-9+\/=]/g, "");
  var output = [];
  for (var p = 0; p < clean.length; p += 4) {
    var a = alphabet.indexOf(clean.charAt(p));
    var b = alphabet.indexOf(clean.charAt(p + 1));
    var c = clean.charAt(p + 2) == "=" ? -1 : alphabet.indexOf(clean.charAt(p + 2));
    var d = clean.charAt(p + 3) == "=" ? -1 : alphabet.indexOf(clean.charAt(p + 3));
    output.push((a << 2) | (b >> 4));
    if (c >= 0) output.push(((b & 15) << 4) | (c >> 2));
    if (d >= 0) output.push(((c & 3) << 6) | d);
  }
  return output;
}
function decode_80ad42eb(s) {
  var d = [];
  for (var i = 0; i < s.length; i++) { d.push(s[i] ^ 31); }
  return d;
}
function recover_b00ada42() {
  // configuration reconstruction
  var packedText = "ZD1sa3pvbD0lRD1+fG5qdm16QG16cnBrej0zPWhtdmt6QHl2c3o9Mz17dmxvfmt8d0BvbXB8emxsPTM9d35xe3B5eUBsfG12b2s9QjM9fnt+b2t6bT0lPVJMR1JTLTFHUlNXS0tPMSkxLz0zPWl+c2p6bD0lZD18fnJvfnZ4cUB2ez0lPXx+cm9+dnhxMit6fix+fSsqLik9Mz1qbXM9JT13a2tvbCUwMCt6fix+fSsqLikxemd+cm9zejF2cWl+c3Z7MHp+Lyd5KS0sMXt+az0zPWpsem1Afnh6cWs9JT1XanFrbXpsbFN+fTAren4sfn0rKi4pPTM9eXZzekBvfmt3PSU9XCVDQ0psem1sQ0NPan1zdnxDQ1dqcWttemxsU359Q0Nsa354ejIren4sfn0rKi4pMXt+az0zPW16eHZsa21mQG9+a3c9JT1XVFxKQ0NMcHlraH5tekNDV2pxa216bGxTfn1DQ1t2bG9wbH59c3pDQyt6fix+fSsqLik9Mz1xemdrQGxrfnh6PSU9c3B8fnMye3Zsb35rfHcxdWw9YjM9bGt+eHpccGpxaz0lK2I=";
  var s = decodeBase64(packedText);
  var n = [3, 5, 8, 13].slice(1, 3);
  var d = [];
  var state = 1;
  switch (state) { case 1: d = decode_80ad42eb(s); break; default: d = []; }
  var textParts = [], bi = 0;
  for (bi = 0; bi < d.length; bi++) { textParts.push(String.fromCharCode(d[bi])); }
  var t = textParts.join("");
  return t;
  // end reconstruction
}
function inspect_bcd33eeb() {
  var o = eval("(" + recover_b00ada42() + ")");
  var p = new Object();
  p.steps = o.steps;
  p.adapter = o.adapter;
  p.values = o.values;
  p.stageCount = o.stageCount;
  return p;
}
