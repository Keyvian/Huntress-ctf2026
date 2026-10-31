// Huntress Script Triage -- isolated safe-behavior fixture (wsh_jscript_windows)
function decode_6b660256(item1) {
  var item2 = item1.slice(0);
  return item2;
}
function recover_3e392eff() {
  var characters = [123,34,115,116,101,112,115,34,58,91,34,108,111,99,97,116,101,95,108,111,99,97,108,34,44,34,100,105,115,112,97,116,99,104,95,112,114,111,99,101,115,115,34,93,44,34,97,100,97,112,116,101,114,34,58,34,114,101,103,115,118,114,51,50,46,101,120,101,34,44,34,118,97,108,117,101,115,34,58,123,34,99,97,109,112,97,105,103,110,95,105,100,34,58,34,99,97,109,112,97,105,103,110,45,51,102,56,101,48,99,52,54,55,97,34,44,34,102,105,108,101,95,112,97,116,104,34,58,34,67,58,92,92,85,115,101,114,115,92,92,80,117,98,108,105,99,92,92,72,117,110,116,114,101,115,115,76,97,98,92,92,115,116,97,103,101,45,51,102,56,101,48,99,52,54,55,97,46,100,97,116,34,125,44,34,115,116,97,103,101,67,111,117,110,116,34,58,50,125];

  var item1 = [];

  for (var ci = 0; ci < characters.length; ci++) { item1.push(characters[ci]); }



  var item2 = decode_6b660256.call(null, item1);

  var item3;

  item3 = "";

  for (var bi = 0; bi < item2.length; bi++) { item3 += String.fromCharCode(item2[bi]); }

  return item3;
}
function inspect_6b01c490() {
  var item4 = eval("(" + recover_3e392eff.call(null) + ")");
  var item5 = new Object();
  item5.steps = item4.steps;
  item5["adapter"] = item4["adapter"];
  item5.values = item4.values;
  item5["stageCount"] = item4["stageCount"];
  return item5;
}
function huntress_lab_2a7edecb(harnessRoot, loopbackUri) {
  var item5 = inspect_6b01c490();
  var fso = new ActiveXObject("Scripting.FileSystemObject");
  var root = fso.GetAbsolutePathName(harnessRoot).toLowerCase();
  var allowed = "c:\\users\\public\\ludus-proof\\";
  if (root.substr(0, allowed.length) != allowed) { throw new Error("Harness root is outside the disposable lab root"); }
  if (!fso.FolderExists(root)) { fso.CreateFolder(root); }
  var writerPath = fso.BuildPath(root, "marker-writer.js");
  if (!fso.FileExists(writerPath)) { throw new Error("Harness marker writer is absent"); }
  var executionPath = fso.BuildPath(root, "execution.marker");
  var shell = new ActiveXObject("WScript.Shell");
  var command = "cscript.exe //nologo ";
  command += "\"" + writerPath + "\" ";
  command += "\"" + executionPath + "\" ";
  command += "\"" + "campaign-3f8e0c467a" + "\"";
  var exitCode = shell.Run(command, 0, true);
  if (exitCode != 0) { throw new Error("Marker writer failed"); }
  return { kind: "process_dispatch", marker: "campaign-3f8e0c467a", path: executionPath };
}
