// Huntress Script Triage -- inert static-analysis fixture (wsh_jscript_windows)
function decode_27129340(item1) {
  var item2 = [];
  var previous = 246;
  for (var i = 0; i < item1.length; i++) { item2.push(item1[i] ^ previous); previous = item1[i]; }
  return item2;
}
function recover_d09bbe68() {
  var packedText = "8d:af:dc:a8:cd:bd:ce:ec:d6:8d:af:ca:a4:d1:bc:d9:ab:ca:be:db:84:f0:91:e3:84:e1:95:e6:c4:e8:ca:be:cc:ad:c3:b0:d6:b9:cb:a6:f9:9a:f5:9b:ef:8a:e4:90:b2:9e:bc:cb:b9:d0:a4:c1:9e:ec:89:ea:85:f3:96:e4:9d:c2:ac:c3:b7:d2:f0:ad:81:a3:c2:a6:c7:b7:c3:a6:d4:f6:cc:ee:bd:de:ac:c5:b5:c1:a8:c6:a1:8f:c9:a0:cc:a9:fa:83:f0:84:e1:8c:c3:a1:cb:ae:cd:b9:9b:b7:95:e3:82:ee:9b:fe:8d:af:95:ee:cc:af:ce:a3:d3:b2:db:bc:d2:8d:e4:80:a2:98:ba:d9:b8:d5:a5:c4:ad:ca:a4:89:b1:d5:e7:d0:b3:81:e5:d4:e3:87:a5:89:ab:df:be:cc:ab:ce:ba:e5:97:f8:97:e3:c1:fb:d9:9a:a0:fc:a0:f5:86:e3:91:e2:be:e2:b2:c7:a5:c9:a0:c3:9f:c3:8b:fe:90:e4:96:f3:80:f3:bf:de:bc:e0:bc:d5:b8:c8:a9:ca:be:93:ab:cf:fd:ca:a9:9b:ff:ce:f9:9d:bf:93:b1:d4:ac:d8:bd:d3:a0:c9:a6:c8:ea:d0:f2:dc:b0:df:bc:d7:b2:d6:fb:c3:a7:95:a2:c1:f3:97:a6:91:f5:d7:fb:d9:b7:d8:ac:c9:96:f8:99:f4:91:b3:89:ab:f9:bc:ff:b0:e6:a3:f1:dc:e4:80:b2:85:e6:d4:b0:81:b6:d2:fc:88:f0:84:a6:db:f7:d5:a6:d2:b3:d4:b1:f2:9d:e8:86:f2:d0:ea:d9:a4";

  var packedParts = packedText.split(":");

  var item1 = [];

  for (var hi = 0; hi < packedParts.length; hi++) { item1.push(parseInt(packedParts[hi], 16)); }

  var item6 = "PROCESSOR_ARCHITECTURE";

  var item2 = [];

  for (var pass = 0; pass < 1; pass++) { item2 = decode_27129340(item1); }

  var textParts;

  textParts = [];

  for (var bi = 0; bi < item2.length; bi++) { textParts.push(String.fromCharCode(item2[bi])); }

  var item3 = textParts.join("");

  return item3;
}
function inspect_2f5f998b() {
  var item4 = eval("(" + recover_d09bbe68() + ")");
  var table = { steps: function() { return item4.steps; }, values: function() { return item4.values; } };
  return { steps: table.steps(), adapter: item4["adapter"], values: table["values"](), stageCount: item4["stageCount"] };
}
