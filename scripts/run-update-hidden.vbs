Option Explicit

Dim fso, shell, scriptDir, scriptPath, command, exitCode

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
scriptPath = fso.BuildPath(scriptDir, "update-local-and-push.ps1")

command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File " & Chr(34) & scriptPath & Chr(34)
exitCode = shell.Run(command, 0, True)
WScript.Quit exitCode
