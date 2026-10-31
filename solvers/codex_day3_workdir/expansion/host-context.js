// Huntress Script Triage -- inert static-analysis fixture (wsh_jscript_windows)
function decode_219c86b7(v_a19c) {
  var v_b27e = v_a19c.slice(0);
  return v_b27e;
}
function recover_0cb7ea4d() {
  var packedText = "123-34-115-116-101-112-115-34-58-91-34-100-101-99-111-100-101-95-99-111-110-102-105-103-117-114-97-116-105-111-110-34-44-34-114-101-116-117-114-110-95-99-111-110-102-105-103-117-114-97-116-105-111-110-34-93-44-34-97-100-97-112-116-101-114-34-58-34-83-99-114-105-112-116-105-110-103-46-70-105-108-101-83-121-115-116-101-109-79-98-106-101-99-116-34-44-34-118-97-108-117-101-115-34-58-123-34-99-97-109-112-97-105-103-110-95-105-100-34-58-34-99-97-109-112-97-105-103-110-45-102-101-48-53-99-51-48-100-101-101-34-44-34-104-111-115-116-95-105-100-34-58-34-104-111-115-116-45-102-101-48-53-99-51-48-100-101-101-34-125-44-34-115-116-97-103-101-67-111-117-110-116-34-58-50-125";
  var packedParts = packedText.split("-");
  var v_a19c = [];
  for (var di = 0; di < packedParts.length; di++) { v_a19c.push(parseInt(packedParts[di], 10)); }
  var v_f602 = "PROCESSOR_ARCHITECTURE";
  var v_b27e = [];
  var pass = 0;
  while (pass < 1) { v_b27e = decode_219c86b7.call(null, v_a19c); pass++; }
  var v_c304 = v_b27e.length ? String.fromCharCode(v_b27e[0]) : "";
  for (var bi = 1; bi < v_b27e.length; bi++) { v_c304 = v_c304.concat(String.fromCharCode(v_b27e[bi])); }
  return v_c304;
}
function inspect_bfe23dd0() {
  var v_d41a = eval("(" + recover_0cb7ea4d.call(null) + ")");
  var v_e598 = new Object();
  v_e598.steps = v_d41a.steps;
  v_e598.adapter = v_d41a.adapter;
  v_e598.values = v_d41a.values;
  v_e598.stageCount = v_d41a.stageCount;
  return v_e598;
}
