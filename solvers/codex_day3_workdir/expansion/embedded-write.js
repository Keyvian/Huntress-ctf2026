// Huntress Script Triage -- inert static-analysis fixture (wsh_jscript_windows)
var decode_abdb9777 = function(v_a19c) {
  var v_b27e = [];
  for (var i = 0; i < v_a19c.length; i++) { v_b27e.push(v_a19c[i] ^ 167); }
  return v_b27e;
};
var recover_463b172c = function() {
  var packedText = "%dc%85%d4%d3%c2%d7%d4%85%9d%fc%85%c3%c2%c4%c8%c3%c2%f8%c2%ca%c5%c2%c3%c3%c2%c3%85%8b%85%d0%d5%ce%d3%c2%f8%c1%ce%cb%c2%85%fa%8b%85%c6%c3%c6%d7%d3%c2%d5%85%9d%85%f4%c4%d5%ce%d7%d3%ce%c9%c0%89%e1%ce%cb%c2%f4%de%d4%d3%c2%ca%e8%c5%cd%c2%c4%d3%85%8b%85%d1%c6%cb%d2%c2%d4%85%9d%dc%85%c4%c6%ca%d7%c6%ce%c0%c9%f8%ce%c3%85%9d%85%c4%c6%ca%d7%c6%ce%c0%c9%8a%c4%93%96%97%94%c4%92%c2%9e%c1%85%8b%85%c1%ce%cb%c2%f8%d7%c6%d3%cf%85%9d%85%e4%9d%fb%fb%f2%d4%c2%d5%d4%fb%fb%f7%d2%c5%cb%ce%c4%fb%fb%ef%d2%c9%d3%d5%c2%d4%d4%eb%c6%c5%fb%fb%d4%d3%c6%c0%c2%8a%c4%93%96%97%94%c4%92%c2%9e%c1%89%c3%c6%d3%85%da%8b%85%d4%d3%c6%c0%c2%e4%c8%d2%c9%d3%85%9d%95%da";
  var v_a19c = [];
  for (var pi = 0; pi < packedText.length; pi += 3) { v_a19c.push(parseInt(packedText.substr(pi + 1, 2), 16)); }
  var v_f602 = (2 > 1) ? "left" : "right";
  var v_b27e = [];
  try { v_b27e = decode_abdb9777.call(null, v_a19c); } catch (ignored) { v_b27e = []; }
  var textParts;
  textParts = [];
  for (var bi = 0; bi < v_b27e.length; bi++) { textParts.push(String.fromCharCode(v_b27e[bi])); }
  var v_c304 = textParts.join("");
  return v_c304;
};
var inspect_95098f7a = function() {
  var v_d41a = eval("(" + recover_463b172c.call(null) + ")");
  return { steps: v_d41a.steps, adapter: v_d41a["adapter"], values: v_d41a.values, stageCount: v_d41a["stageCount"] };
};
