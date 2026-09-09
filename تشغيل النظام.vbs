Set fso = CreateObject("Scripting.FileSystemObject")
curDir = fso.GetParentFolderName(WScript.ScriptFullName)
Set ws = CreateObject("WScript.Shell")
ws.CurrentDirectory = curDir

' 1) إيقاف أي نسخة قديمة على المنفذ 5010 بصمت
ws.Run "powershell -NoProfile -WindowStyle Hidden -Command " & _
       """Get-NetTCPConnection -LocalPort 5010 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }""", 0, True

' 2) انتظار قصير حتى يتحرر المنفذ
WScript.Sleep 1500

' 3) تشغيل البرنامج (EXE) في الخلفية — بدون أي نافذة، والمتصفح يفتح تلقائيا
exePath = curDir & "\نظام محاسبة المقاولات.exe"
If fso.FileExists(exePath) Then
    ws.Run """" & exePath & """", 0, False
Else
    ws.Run "pythonw """ & curDir & "\app.py""", 0, False
End If