#!/usr/bin/env pwsh
Param(
    [Parameter(Mandatory=$False)]
    [switch]$PreparePxe
)

function Packer-BuildAppliance {
	param([Parameter()][string]$SearchFileName, [Parameter()][string]$Filter, [Parameter()][string]$ArgList)
	$runit = $false
	if ([System.String]::IsNullOrEmpty($SearchFileName)) {
		$runit = $true
	} else {
		$files = [System.IO.Directory]::GetFiles($PWD.ProviderPath + "/output", $SearchFileName, [System.IO.SearchOption]::AllDirectories)	
		if (-Not([System.String]::IsNullOrEmpty($Filter))) {
			$files = [Linq.Enumerable]::Where($files, [Func[string,bool]]{ param($x) $x -match $Filter })
		}
		$file = [Linq.Enumerable]::FirstOrDefault($files)
		Write-Host $file
		if ([System.String]::IsNullOrEmpty($file)) {
			$runit = $true
		}
	}
	if ($runit) {
		if ($IsWindows -or $env:OS) {
			$process = Start-Process -PassThru -Wait -NoNewWindow -FilePath "packer.exe" -ArgumentList $ArgList
			return $process.ExitCode
		} else {
			$process = Start-Process -PassThru -Wait -FilePath "packer" -ArgumentList $ArgList
			return $process.ExitCode
		}
	}
	return 0
}

New-Item -Path $PWD.ProviderPath -Name "output" -ItemType "directory" -Force | Out-Null
$env:PACKER_LOG=1
# QEMU
$env:PACKER_LOG_PATH="output/mikrotik-packerlog.txt"
if ((Packer-BuildAppliance -SearchFileName "*mikrotik*.qcow2" -ArgList "build -force -on-error=ask -only=qemu.default mikrotik.pkr.hcl") -ne 0) {
	break
}
