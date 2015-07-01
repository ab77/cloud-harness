# unpack custom-data and execute contents

$custom_data_file = "C:\AzureData\CustomData.bin"
$bootstrap_script = "$env:TEMP\custom_data.ps1"

if (Test-Path $custom_data_file) {
	Write-Host "Processing custom-data..."
	$custom_data = Get-Content $custom_data_file
	[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($custom_data)) > $bootstrap_script
	& powershell.exe -ExecutionPolicy Unrestricted -File $bootstrap_script

} else {
	Write-Host "$custom_data_file not found"
}