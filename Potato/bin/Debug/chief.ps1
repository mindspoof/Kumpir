param (
	[Parameter(Mandatory=$true)][string]$ps,
	[Parameter(Mandatory=$true)][string]$file,
	[byte]$iter = 3
)

$command = [IO.file]::ReadAllText((Resolve-Path $ps))
$command = $command + "Read-Host 'Script Blocked. Press any key to finish'"

$encodedCommand = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))

For ($i = 0; $i -ne $iter; $i++){

	$memory_stream = New-Object System.IO.MemoryStream
	$comp_stream = New-Object System.IO.Compression.GZipStream($memory_stream, [System.IO.Compression.CompressionMode]::Compress)
	$stream_writer = New-Object System.IO.StreamWriter($comp_stream)

	$stream_writer.Write($encodedCommand)
	
	$stream_writer.Close()
	$final_str = [System.Convert]::ToBase64String($memory_stream.ToArray())
	
	$encodedCommand = $final_str

}

$split = "<split>"
$split_end = "</split>"

echo $split | Out-File -FilePath $file -Append -Encoding UTF8 -NoNewLine
Add-Content -Path $file -Value $iter -Encoding Byte
echo $final_str | Out-File -FilePath $file -Append -NoNewLine
echo $split_end | Out-File -FilePath $file -Append -Encoding UTF8 -NoNewLine

$stream_writer.Close()
$memory_stream.Close()
$stream_writer.Dispose()
$memory_stream.Dispose()