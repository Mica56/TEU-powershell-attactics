# Send-MailMessage -To “<recipient’s email address>” -From “<sender’s email address>”  -Subject “Your message subject” -Body “Some important plain text!” -Credential (Get-Credential) -SmtpServer “<smtp server>” -Port 587
$From = "mother-of-dragons@houseoftargaryen.net"
$To = "jon-snow@winterfell.com"
$Attachment = "C:\Temp\Drogon.jpg"
$Subject = "Photos of Drogon"
$Body = "<h2>Guys, look at these pics of Drogon!</h2><br><br>"
$Body += “He is so cute!”
$SMTPServer = "smtp.mailtrap.io"
$SMTPPort = "587"
Send-MailMessage -From $From -to $To -Subject $Subject -Body $Body -BodyAsHtml -SmtpServer $SMTPServer -Port $SMTPPort -UseSsl -Credential (Get-Credential) -Attachments $Attachment