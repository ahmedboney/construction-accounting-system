Set ws = CreateObject("WScript.Shell")
' إيقاف أي عملية تعمل على المنفذ 5010 بصمت تام
ws.Run "powershell -NoProfile -WindowStyle Hidden -Command " & _
       """Get-NetTCPConnection -LocalPort 5010 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }""", 0, True