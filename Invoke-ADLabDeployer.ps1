
<#
    Invoke-ADLabDeployer - Automated Windows and AD testlab deployments for red and blue teams
    Author: Marc Smeets / Outflank B.V.
    License: BSD 3-Clause
    Version: 0.8
    Date: 30 March 2018
    Link: https://github.com/OutflankNL/Invoke-ADLabDeployer / https://outflank.nl/blog/2018/03/30/automated-ad-and-windows-test-lab-deployments-with-invoke-adlabdeployer

#>


function Invoke-ADLabDeployer {
    <#
    .Synopsis
       Start of the automated AD lab deployment.

    .DESCRIPTION
       Main function to start for the automated lab deployment. Requires the following parameters: 
       1. path to lab definition file.
       2. The name of the lab you want to build -as defined in the lab definition file. 
      
    .EXAMPLE
       Deploy the network LabX as defined in lab-config file .\configs\lab.xml
       InvokeAD-LabDeployment -LabConfigFile configs\lab.xml -LabName LabX

    .EXAMPLE
       Deploy a lab with verbose intermediate output
       Invoke-ADLabDeployment -LabConfigFile configs\lab.xml -LabName LabX -Verbose

    .EXAMPLE
       Check the configuration of LabX for validity 
       Invoke-LabDeployment -LabConfigFile configs\lab.xml -LabName LabX -CheckConfigOnly

    .EXAMPLE
       Check the config andstore the resulting objects as local objects
       $return_net,$return_sys,$return_adds = Invoke-ADLabDeployer -LabConfigFile configs\lab.xml -Name LabX -CheckConfigOnly 

    .PARAMETER $LabConfigFile
        The file containing the lab configuration - mandatory

    .PARAMETER $Name
        The name of the lab inside the lab config file - mandatory

    .PARAMETER $CheckConfigOnly
        When set will only parse the config file but will not deploy the lab - not mandatory

    #>

    [CmdletBinding()]
    Param
    (
	[Parameter(Mandatory = $True)]
	[String]
	[ValidateNotNullOrEmpty()]
	$LabConfigFile,

	[Parameter(Mandatory=$True)]
	[string]
	$Name,

    [parameter(Mandatory=$false)]
    [switch]
    $CheckConfigOnly = $false
    )

    [hashtable]$HTSystems = [ordered]@{}	# hash table with details of systems to deploy
    [hashtable]$HTNetworks =[ordered]@{}	# hash table with details of networks to deploy
    [hashtable]$HTAdds =[ordered]@{}		# hash table with details of AD domains to deploy
    
    if (-not($CheckConfigOnly)) {
        Write-Verbose "[*] Start lab deployment"
        $StartTime = Get-Date
    }

    ## Opening the lab config file - exit on error.
    try { 
        [xml]$LabConfig = Get-Content -Path "$LabConfigFile" 
    }
    catch { 
        $_
        Write-Error "[X] ERROR: could not read $LabConfigFile. Now exiting."
        Break
    }
    finally {
        Write-Verbose "[+] Successfully opened $LabConfigFile"
    }

    ## Getting network info from lab config file - exit on error.
    try { 
        foreach ($Net in $LabConfig.SelectNodes("/Labs/Lab[@LabName=`""+ $Name + "`"]/Network")) {
        [hashtable]$HTTempNetwork=  [ordered]@{}
        $HTTempNetwork.Add("NetName", $Net.NetName)
        $HTTempNetwork.Add("Subnet", $Net.Subnet)
        $HTTempNetwork.Add("GW", $Net.GW)
        $HTNetworks.Add($Net.NetName, $HTTempNetwork)
        Write-Verbose "[+] Successfully processed config of network: $($Net.NetName)"
        }
    }
    catch {
        Write-Error "[X] ERROR: could not process network config in XML. Exiting."
        Break
    }
    finally {
        Write-Verbose "[+] Successfully processed network config. Amount of networks read: $($HTNetworks.Count)."
    }

    ## getting system config from lab config file - exit on error
    try {
        foreach ($VM in $LabConfig.SelectNodes("/Labs/Lab[@LabName=`""+ $Name + "`"]/System")) {
            [hashtable]$HTTempSystem=  [ordered]@{}
            if (-not ($VM.SkipDeploy -like "True")) {
                $HTTempSystem.Add("Hostname", $VM.Hostname)
                $HTTempSystem.Add("OS", $VM.OS)
                if ( ($VM.OS -like "*indows7*") -or ($VM.OS -like "*indows8*") -or ($VM.OS -like "*indows8.1*") -or ($VM.OS -like "*indows10*") ) {
                    $HTTempSystem.Add("Type", "Client")
                } else { 
                    $HTTempSystem.Add("Type", "Server")
                }
                if (-not (get-ChildItem "configs\$($VM.UnattendFile)" -ErrorAction SilentlyContinue )) {
                    Write-Error "[X] ERROR: could not find unattend file for system "($VM.Hostname).ToString()
                    Break
                } else { $HTTempSystem.Add("UnattendFile", $VM.UnattendFile) }
                $HTTempSystem.Add("User", $(($VM.LocalCreds).split(':')[0]))
                $HTTempSystem.Add("Pass", $(($VM.LocalCreds).split(':')[1]))
                if (-not (get-ChildItem "disks\parentdisks\$($VM.ParentDisk).vhdx" -ErrorAction SilentlyContinue)) {
                    Write-Error "[X] ERROR: could not find parent disk for system "($VM.Hostname).ToString()
                    Break
                } else { $HTTempSystem.Add("ParentDisk", $VM.ParentDisk) }
                $HTTempSystem.Add("Net1_Name", $VM.Net1_Name)
                $HTTempSystem.Add("Net1_MAC", $(Get-MacAddress))
                $HTTempSystem.Add("Net1_IP", $VM.Net1_IP)
                # If not explicitly set in lab config file, set DNS server to IP address of PDC if system is in Domain, or to 9.9.9.9 if not in domain.
                # We havent parsed the ADDS settings yet, and so dont know PDC value yet. We'll just set a temp value 'PDC' here and alter after ADDS parsing.
                if (-not ($VM.Net1_DNS)) {
                    if ($VM.Domain) {
                        $HTTempSystem.Add("Net1_DNS","PDC")
                    } else { 
                        $HTTempSystem.Add("Net1_DNS","9.9.9.9")
                    }
                } else { 
                    $HTTempSystem.Add("Net1_DNS", $VM.Net1_DNS)
                } 
                #setting the Gateway to the value defined in the network definition
                $GWAddress = $HTNetworks.item($vm.Net1_Name).item("GW")
                $HTTempSystem.Add("Net1_GW", $GWAddress)

                if ($VM.Win_Update) { 
                    $HTTempSystem.Add("Win_Update", $VM.Win_Update)
                }
                if ($VM.Domain) {
                    $HTTempSystem.Add("Domain", $VM.Domain)
                }
                if ($VM.RDP_Allow) {
                    $HTTempSystem.Add("RDP_Allow", $VM.RDP_Allow)
                }
                # Setting the VMname to labname + hostname + ip address + OS name ( + office version if lab xml contains office settings)
                if ($VM.OfficeInstaller) {
                    $HTTempSystem.Add("OfficeInstaller", $VM.OfficeInstaller)
                    $HTTempSystem.Add("OfficeConfig", $VM.OfficeConfig)
                    $HTTempSystem.Add("VMName", $($Name+"_"+$VM.HostName+"_"+$(($VM.Net1_IP).split('/')[0])+"_"+$VM.OS+"_"+$(($VM.OfficeConfig).split('\')[0])))
                } else {               
                    $HTTempSystem.Add("VMName", $($Name+"_"+$VM.HostName+"_"+$(($VM.Net1_IP).split('/')[0])+"_"+$VM.OS))
                }
                # Adding SW_JustCopy if set
                if ($VM.SW_JustCopy) {
                    $HTTempSystem.Add("SW_JustCopy", $VM.SW_JustCopy)
                }
                # Adding SW_Install if set
                if ($VM.SW_Install) { $HTTempSystem.Add("SW_Install", $VM.SW_Install) }
                
                # Setting memory from value in lab config file, or based on Type. Servers = 2GB, Clients = 4GB
                if ($VM.Mem) {
                    $HTTempSystem.Add("Mem", $VM.Mem)
                } else {
                    if ($($HTTempSystem.item("Type")) -match "Client") {
                        $HTTempSystem.Add("Mem", "4GB")
                    } else {
                        $HTTempSystem.Add("Mem", "2GB")
                    }
                }
                
                # Adding it all to the hashtable
                $HTSystems.Add($VM.Hostname, $HTTempSystem)
                Write-Verbose "[+] Successfully processed config of system: $($VM.Hostname)"
            }
        }
    }
    catch {
        Write-Error "[X] ERROR: could not process system config in XML. Exiting."
        Write-Error "[X] ERROR: have processed so far: "+$HTTempSystem
        Break
    }
    finally {
        Write-Verbose "[*] Done processing system config in XML. Amount of systems read: $($HTSystems.Count)."
    }

    ## getting AD config from lab config file - exit on error
    try {
        foreach ($Domain in $LabConfig.SelectNodes("/Labs/Lab[@LabName=`""+ $Name + "`"]/ADDS")) {
            Write-Verbose "[*] Start processing config of an ActiveDirectory Domain Services."
            [hashtable]$HTTempDomain=  [ordered]@{}
            $HTTempDomain.Add("ADDSName", $Domain.ADDSName)
            $HTTempDomain.Add("ParentDomain", $Domain.ParentDomain)
            $HTTempDomain.Add("PDC", $Domain.PDC)
            $HTTempDomain.Add("SafeModeAdminPass", $Domain.SafeModeAdminPass)
            $HTTempDomain.Add("PDC_IP", $($HTSystems.$($Domain.PDC).Net1_IP).split('/')[0])
            $HTTempDomain.Add("PDC_LocalUser", $($HTSystems.$($Domain.PDC).User))
            $HTTempDomain.Add("PDC_LocalPass", $($HTSystems.$($Domain.PDC).Pass))
            $HTAdds.Add($Domain.ADDSName, $HTTempDomain)
            Write-Verbose "[+] Successfully processed config of AD domain: $($Domain.ADDSName)"
        }
    }
    catch  {
        Write-Error "[X] ERROR: could not process AD config in XML. Exiting."
        Break
    }
    finally {
        Write-Verbose "[*] Done processing AD config in XML. Amount of AD domains read: $($HTAdds.Count)."
    }

    # Revisiting DNS info now that we have parsed the ADDS info
    Try {
        foreach ($VM in $HTSystems.Values) { 
            if ( $vm.item("Net1_DNS") -Like "PDC" ) {
                $domainName = $HTSystems.item($($vm.Hostname)).item("Domain")
                $nameOfPDC = $HTAdds.item($domainName).item("PDC")
                # if we are processing the Domain Controller itself, we better set it to 127.0.0.1 as it will also run a DNS server
                if ($nameOfPDC -Like $vm.Hostname) { 
                    $ipOfPDC = "127.0.0.1"
                }
                else { 
                    $ipOfPDC = ($HTSystems.item($nameOfPDC).item("Net1_IP").split('/')[0])
                }
                $HTSystems.item($($vm.Hostname)).item("Net1_DNS") = $ipOfPDC
            }
        }
    }
    catch {
        Write-Error "[X] ERROR: could not set DNS address from PDC info. Exiting."
        Break
    }
    finally {
        Write-Verbose  "[*] Done adjusting DNS info for Domain joined systems."
    }

    if ($Debug) {
        Write-Debug "Networks found: "
        $HTNetworks
        write-debug "Details of networks found."
        $HTNetworks.values
        Write-Debug "AD domains found: "
        $HTAdds
        write-Debug "Details of AD domains found"
        $HTAdds.values
        Write-Debug "Systems found: "
        $HTSystems
        write-debug "Details of systems found"
        $HTSystems.values
    } 
    write-Verbose "[*] Done reading the lab config file"
    
    # Exit and return objects if parameter -CheckCOnfigOnly was set
    if ($CheckConfigOnly) { 
        return $HTNetworks,$HTSystems,$HTAdds
        Break 
    }

    # Start deployment of network stuff - call one function to do this all
    Invoke-ADLabDeployNetwork -Networks $HTNetworks -LabName $Name
    
    # Create directory for vhd storage for this lab
    if (-not (Test-Path -Path disks\$LabName )) { New-Item "disks\$LabName" -type directory } 
    
    # start deployment of systems - call function per machine
    write-Verbose "[*] Start setting up systems"
    foreach ($VM in $HTSystems.Values) { 
        Invoke-ADLabDeployVM -Machine $VM -LabName $Name 
    }
    Write-Verbose "[+] Done setting up the VM(s) and now starting them up. Giving them 180s to boot."
    Start-Sleep -Seconds 180

    # Start deployment of AD Services - call function per domain/forest
    if ($HTadds) {
        $DomainName = $HTAdds.Addsname
        Write-Verbose "[*] Checking if PDC is up"
        # Check if specific system is up
        foreach ($Domain in $htadds.Values) {
            if (Get-ADLabSystemUpStatus -ip $Domain.item("PDC_IP") -username $Domain.item("PDC_LocalUser") -password $Domain.item("PDC_LocalPass") -timeout 120) {   
                Write-Verbose "[*] System is up. Start building ADDS"
                Invoke-ADLabDeployADDS -Domain $Domain -LabName $Name
            } else {
                # Host system is slow in bringing up systems, so wait another few minutes
                Write-Verbose "[*] System is not up. Sleeping 180 seconds"
                Start-Sleep -Seconds 180
                Invoke-ADLabDeployADDS -Domain $Domain -LabName $Name 
            } 
        }
    } else {
        Write-Verbose "[*] No ADDS defined in config file, skipping ADDS setup."
    }

    # Have system join the domain
    if ($HTAdds) {
        foreach ($Domain in $HTAdds.Values) {
            $DNSSearchString = "_ldap._tcp.pdc._msdcs."+$Domain.item("ADDSName")
            $DNSServerIP = $Domain.item("PDC_IP")
            $ADDSIsUp = $False
            # check if ADDS is up by doing a dns lookup for the srv record _ldap._tcp.pdc._msdcs.ADDSNAME
            while (-not($ADDSIsUp)) {
                Write-Verbose "[*] Verifying if DNS server $DNSServerIP is giving out a SRV type record on $DNSSearchString"
                $result = Resolve-DnsName -Name $DNSSearchString -type SRV -Server $DNSServerIP -ErrorAction SilentlyContinue
                if ($?) {
                    Write-Verbose "[+] SRV record found. Continuing with domain join."
                    $ADDSIsUp = $True
                } else {
                    Write-Verbose "[+] SRV record not found. Sleeping for 10 seconds."
                    Start-Sleep -Seconds 10
                }
            }
        }
        # Now we know for sure that the ADDS is up and DNS SRC record available, Start deployment of systems by joining the domain first - call function per system
        Write-Verbose "[*] Joining systems to AD Domains"
        foreach ($VM in $HTSystems.Values) {
            if ($VM.containskey("Domain")) {
                Invoke-ADLabJoinDOmain -Machine $VM -DomainAdminUsername "administrator" -DomainAdminPassword $($HTAdds.item($($VM.item("Domain"))).item("SafeModeAdminPass")) -DCname $($HTAdds.item($($VM.item("Domain"))).item("PDC"))
            }
        }
    }

    # Start installation of software packages - call function per system
    Write-Verbose "[*] Starting installation of software packages."
    foreach ($VM in $HTSystems.Values) {
        Invoke-ADLabSystemInstallSoftware -Machine $VM        
    }

    # Start local configuration of system - call function per system
    Write-Verbose "[*] Starting local configuration."
    foreach ($VM in $HTSystems.Values) {
        Invoke-ADLabSystemLocalConfig -Machine $VM     
    }

    if (-not($CheckConfigOnly)) {
        Write-Verbose "[*] Done with lab deployment."
        $RunTime = [math]::Round((New-Timespan -Start $StartTime -End (Get-Date)).TotalMinutes)
        Write-verbose "[*] Deployed $($HTNetworks.Count) networks,  $($HTAdds.Count) Domain and $($HTSystems.count) systems in $RunTime minutes."
    }
} # end of function Invoke-ADLabDeployer

function Get-MacAddress  {
    <#
    .Synopsis
        Get an unique and valid MAC address.

    .DESCRIPTION
        Generates and returns a MAC address that is not used on any VM registerd on the current host. 
        Mac address is in XX-XX-XX-XX-XX-XX format.
        
        Its not a fully random generated address as these can become invalid addresses. 
        This function lets the address start with 06 to have a locally generated unicast address  
      
    #>

    $currentMacs = get-vm|ForEach-Object{(Get-VMNetworkAdapter -VMName $_.Name).MacAddress }
    
    $unique = $False
    while (-not $unique) { 
        $mac = "06-"+$((0..4 | ForEach-Object { '{0:x}{1:x}' -f (Get-Random -Minimum 0 -Maximum 15),(Get-Random -Minimum 0 -Maximum 15)})  -join '-')
        if (-not($currentMacs -contains $mac)) {$unique = $true}
    }     
    return $mac
}

Function Invoke-ADLabDeployNetwork {
<#
    .Synopsis
       Deploy virtual network

    .DESCRIPTION
      Function to deploy the virtual network. 
          
    .EXAMPLE
       Invoke-ADLabDeployNetwork -Networks $HTNetworks -LabName $Name

    .PARAMETER $Networks
        hashtable with info on the networks - mandatory

    .PARAMETER $LabName
        String with the name of the lab - required for naming the virtual switches - mandatory
#>    
    
    [CmdletBinding()]
    param (
    [Parameter(Mandatory = $True)]
	[hashtable]
	[ValidateNotNullOrEmpty()]
	$Networks,

   	[Parameter(Mandatory=$True)]
	[string]
	$LabName 
    )

    ############################################
    ######  1. Setting up the network
    # Todo: do more advanced networking, where lab config file can be used to determine detailed routing setup. 
    # Preferably using true Hyper-V Network Virtualization (RRIDs, CA, PA, etc.).
    # For now we use old skool style RRAS server functionality installed on the Hyper-V server. This setup is not officially supported by MSFT but it works. Yolo!
    #
    # Todo: cleaner way of setting current configs.
    # Now we rather brute force delete several existing configs: NetNat switches, RRAS configs and vEthernet internal switches.
    write-Verbose "[*] Start setting up the virtual network"
    Write-Verbose "[+] Removing netnat networks as they interfere with our desired setup" 
    get-netnat|remove-netnat

    # Check if RRAS Windows feaute is installed. If not, warn and exit.
    if (-not(Get-Service remoteaccess -RequiredServices)) {
        write-Error "[X] Remote Access deamon RRAS not installed. This is required."
        Write-Error "[X] To install run:"
        Write-Error "[X]   1. Install-WindowsFeature Routing -IncludeManagementTools"
        Write-Error "[X]   2. Set-Service remoteaccess -StartupType automatic"
        Write-Error "[X]   3. Set-Service rasman -StartupType automatic"        Write-Error "[X]   4. Restart-Computer"
        Write-Error "[X] Can't continue, exiting now."        Break
    }

    # check if Routing is enabled. If not do so.
    $routingEnabled = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name IPEnableRouter).IPEnableRouter
    if ($rouingEnabled -match "0") {
        write-verbose "[+] Enabling routing"
        New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name IPEnableRouter -value 1 -Force 
    } else {
        write-verbose "[*] Routing already enabled"
    }
    
    ## Setting up the virtual switches and networks for the VMs
    foreach ($Net in $Networks.Values) { 
        # setting the name of the switch to labname_netname
        $SwitchName =  $LabName+"_"+$Net.item("NetName")
        Write-Verbose "[*] Processing virtual switch $SwitchName"

        # Check if switch name not exists or GW IP address not exists - if both not exist we can safely make the new switch
        if ((-not(get-vmswitch $SwitchName -ErrorAction SilentlyContinue)) -and ( -not(Get-NetIPAddress -IPAddress $($Net.item("GW")) -ErrorAction SilentlyContinue))) {
            # Make new switch
            Write-Verbose "[+] Virtual switch $SwitchName not found, creating."
            New-VMSwitch -Name $SwitchName -SwitchType Internal -Notes "Internal switch for lab $LabName" | Out-Null
        
            # Set the adapter for the switch
            Write-Verbose "[+] Setting up the new interface  $SwitchName"
            New-NetIPAddress -interfaceAlias "vEthernet ($SwitchName)" -IPAddress $($Net.item("GW")) -PrefixLength $(($Net.item("Subnet")).split('/')[1]) | Out-Null

        } else { # either switchname exists or GW ip address exsits
            # check if the interface with correct IP address is attached to correct switchname, if not something is wrong and we exit
            if (Get-NetIPAddress -IPAddress $($Net.item("GW")) | select interfaceAlias | where {$_.InterfaceAlias -match $SwitchName } ) {
                Write-Verbose "[*] Virtual switch $SwitchName found with correct IP address, no further config needed."
       
            } else {
                Write-Error "[X] Interface found with GW IP address, but not attached to virtual switch $SwitchName." 
                Write-Error "[X] Something is wrong, please fix this manually."
                Break
            } 
        }
    }

    Write-verbose "[+] Successfully setup virtual network."
} # end of function Invoke-ADLabDeployNetwork

function Invoke-ADLabDeployVM {
    <#
    .Synopsis
       Deploy a virtual machine

    .DESCRIPTION
      Function to deploy a virtual machine. 
          
    .EXAMPLE
      Invoke-ADLabDeployVM -Machine $VM -LabName $Name

    .PARAMETER $VM
        Hastable with info on the virtual machine - mandatory

    .PARAMETER $LabName
        String with the name of the virtual machine - mandatory

    .PARAMETER $UpdateParent
        Boolean required when updating updates on the parent images - not mandatory
        Most likely only used when called from Invoke-ADLabImageUpdater

    #>    

    [CmdletBinding()]
    param (
    [Parameter(Mandatory = $True)]
	[hashtable]
	[ValidateNotNullOrEmpty()]
	$Machine,

   	[Parameter(Mandatory=$True)]
	[string]
	$LabName,    

    [Parameter(Mandatory = $False)]
    [Boolean]
    $UpdateParent = $False
    )

    # We prefer generation 2 vms. But this is only supported if 64bit desktop OS is Win8 or later, or server OS is win2012 or later (32 and 64bit)
    # We use the Lab XML config file OS property to check this. Isnt fool proof, but works for now.
    if (($($Machine.item("OS")) -like "*windows7*") -or ($($Machine.item("OS")) -like "*windows8x86*") -or ($($Machine.item("OS")) -like "*windows8.1x86*") -or ($($Machine.item("OS")) -like "*windows10x86*")  -or ($($Machine.item("OS")) -like "*windows2008*")) {
    	$Gen = 1
	} else {
		$Gen = 2
	}
    Write-Verbose "[+] Creating new VM: $($Machine.item("VMName"))"
    
    if ($UpdateParent) {
        $Disk = $("disks\parentdisks\"+$Machine.Item("BaseDisk"))
    } else {
        $Disk = "disks\$LabName\$($Machine.item("VMName")).vhdx"
        New-VHD -Differencing -Path $Disk -ParentPath "disks\parentdisks\$($Machine.item("ParentDisk")).vhdx" | Out-Null
    }
    
    # Make the new VM, attach disk, set amount of memory and attach network
    New-VM -Name $Machine.item("VMName") -Generation $Gen -SwitchName $($LabName+"_"+$Machine.item("Net1_Name")) | Out-Null
    Add-VMHardDiskDrive -VMName $Machine.item("VMName") -Path $Disk | Out-Null
    Set-VMMemory -VMName $Machine.item("VMName") -DynamicMemoryEnabled $True -MaximumBytes $(invoke-expression $Machine.item("Mem")) | Out-Null
    Set-VMNetworkAdapter -VMName $Machine.item("VMName") -StaticMacAddress $Machine.item("Net1_MAC") | Out-Null

    # set boot priority to boot form hard disk to speed up booting proces: different commands for gen1 and gen2
    if ( $Gen -eq 1 ) { 
        Set-VMBios -VMName $Machine.item("VMName") -StartupOrder @("IDE","CD","LegacyNetworkAdapter","Floppy")
    } else { 
        Set-VMFirmware -VMName $Machine.item("VMName") -FirstBootDevice $(Get-VMHardDiskDrive -VMName $Machine.item("VMName"))
    }

    # Performing post install config by mounting the VHD drive and adjusting the unattend.xml.
    # first mount the VHD drive and get the drive letter it is mounted on
    try{ 
        $drive = Mount-VHD -Path $Disk  -Passthru | Get-Disk | Get-Partition|Get-Volume
        # We need to figure out which drive letter the Windows partition is mounted on.
        # Modern Windows disks have multiple partitions with a recovery partition that also get automounted with 'Mount-VHD'. 
        # So checking for drive letter larger than 500MB, and no recovery||reserved in disk label to get the Windows partition
        if ( $drive.count -gt 1 ) {
            foreach ($part in $drive) { 
                if ( $part.size -gt 5000000000 -and $part.filesystemlabel -notlike "*Reserve*" -and $part.FileSystemLabel -notlike "*recovery*") {
                    Write-Debug "[*] partition  $($part.DriveLetter) with size $($part.size) selected"
                    $driveletter = $part.DriveLetter
                }
            }
        } else {
            # Only 1 partition.
            $driveletter = $part.DriveLetter
        }
            
        # Read and modify the unattend.xml file on the new VHD.
        try {
            # Post boot commands to add to the unattend.xml file
            Write-Debug "[*] Attempting to read example xml file configs\$($machine.item("UnattendFile"))"
            Write-Debug "[*] Amount of DNS servers found in config file: $(($machine.item("Net1_DNS")).split(',').count)"
            if ( ($machine.item("Net1_DNS")).split(',').count -eq 1 ) {
                (Get-Content configs\$($machine.item("UnattendFile"))) | Foreach-Object {
                    $_ -replace '@@Hostname@@', $machine.item("Hostname") `
                    -replace '@@Net1_MAC@@', $machine.item("Net1_MAC") `
                    -replace '@@Net1_IP@@', $machine.item("Net1_IP") `
                    -replace '@@Net1_GW@@', $machine.item("Net1_GW") `
                    -replace '@@Net1_DNS@@', $machine.item("Net1_DNS") `
                    -replace '@@DNS_SUFFIX@@', $machine.item("Domain") `
                    -replace '@@User@@', $machine.item("User") `
                    -replace '@@Pass@@', $machine.item("Pass")
                } | Set-Content "${driveletter}:\windows\Panther\unattend.xml"
            } else {
                # Unattand file requires full XML format for multiple DNS servers, nasty but working way to add the XML format for the 2nd DNS server.
                $dnsstring = ($machine.item("Net1_DNS")).split(',')[0] + '</IpAddress> <IpAddress wcm:action="add" wcm:keyValue="2">'+($machine.item("Net1_DNS")).split(',')[1] + '</IpAddress>'
                Write-Debug "[*] Writing DNS info $dnsstring"
                (Get-Content configs\$($machine.item("UnattendFile"))) | Foreach-Object {
                    $_ -replace '@@Hostname@@', $machine.item("Hostname") `
                    -replace '@@Net1_MAC@@', $machine.item("Net1_MAC") `
                    -replace '@@Net1_IP@@', $machine.item("Net1_IP") `
                    -replace '@@Net1_GW@@', $machine.item("Net1_GW") `
                    -replace '@@Net1_DNS@@</IpAddress>', $dnsstring `
                    -replace '@@DNS_SUFFIX@@', $machine.item("Domain") `
                    -replace '@@User@@', $machine.item("User") `
                    -replace '@@Pass@@', $machine.item("Pass")
                } | Set-Content "${driveletter}:\windows\Panther\unattend.xml"
            }
        } catch {
            Write-Warning "[!] WARNING: something went wrong with editing the xml file. It may still be good (by accident), continuing with that positive vibe...."
        } 
    } catch {
        Write-Error "[X] ERROR: could not mount VHD disk to modify unattend.xml file. Exiting."
        break
    }
    Dismount-VHD -Path $Disk
    Write-Verbose "[+] VM $($Machine.item("VMName")) created, now booting."
    Start-VM $machine.item("VMName")

    # Adding system to local Trusted Host list for WSMan if TrustedHost is not already set to wildcard *
    $trustedHostList = Get-Item WSMan:\localhost\Client\TrustedHosts
    if ( -not($trustedHostList.value -Like "*")) {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $machine.item("Net1_IP") -Concatenate -Force
    }

} # end of function Invoke-ADLabDeployVMs

function Get-ADLabSystemUpStatus {
    <#
    .Synopsis
       Check if a system is up 

    .DESCRIPTION
      Helper function for checking status of system. 
      Returns True if system is up and able to log in. 
          
    .EXAMPLE
      Get-ADLabSystemUpStatus -ip $domain.item("PDC_IP") -username $domain.item("PDC_LocalUser") -password $domain.item("PDC_LocalPass") -timeout 15

    .EXAMPLE
      Get-ADLabSystemUpStatus -ip "1.2.3.4" -username "localdminuser" -password "str0ngPasswd!" -timeout 15

    .PARAMETER $IP
        String with the IP address of the host we want to check - mandatory

    .PARAMETER $Username
        String with the username ofa local user on the remote system - mandatory

    .PARAMETER $Password
        String with the password of the local user on the remote system - mandatory 
    
    .PARAMETER $TimeOut
        Integer with value of timeout in seconds to keep trying the remote system - not mandatory
        The timeout value is not accurate. Expect it to be surpassed by ~20sec.
    #> 

    [CmdletBinding()]
    param 
    (
    [Parameter(Mandatory = $True)]
	[String]
	[ValidateNotNullOrEmpty()]
	$IP,

    [Parameter(Mandatory = $True)]
	[String]
	[ValidateNotNullOrEmpty()]
	$Username,

    [Parameter(Mandatory = $True)]
	[String]
	[ValidateNotNullOrEmpty()]
	$Password,

    [Parameter(Mandatory = $False)]
	[Int]
	$TimeOut = 60
    )
     
    $Pass = ConvertTo-SecureString $Password -AsPlainText -Force
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential $Username,$Pass
       
    $StopTime = (get-date).AddSeconds($TimeOut)
    while ((get-date) -lt ($StopTime)) {
        # first do a ping, if successful try a login
        if (Test-Connection -Computername $IP -Count 1 -Quiet|Out-Null) { 
            Invoke-Command -ComputerName $IP -Credential $Creds -ScriptBlock { hostname }|out-null
            if ($?) { 
                return $True
            }
        } 
    }
    # Just in case ping is disabled on the remote host, just one final try with invoke-command
    Invoke-Command -ComputerName $IP -Credential $Creds -ScriptBlock { hostname }|out-null
    if ($?) { 
        return $True
    }
    return $False
 } # end of function Get-ADLabSystemUpStatus

function Invoke-ADLabDeployADDS {
    <#
    .Synopsis
       Deploy the ADDS

    .DESCRIPTION
      Function to deploy the Active Directory Domain Services. 
          
    .EXAMPLE
      Invoke-ADLabDeployADDS -Domain $Domain -LabName $Name

    .PARAMETER $Domain
      Hastable with info on the AD setup - mandatory

    .PARAMETER $LabName
      String with the name of the lab - mandatory

    #>

    [CmdletBinding()]
    param (
    [Parameter(Mandatory = $True)]
	[hashtable]
	[ValidateNotNullOrEmpty()]
	$Domain,

   	[Parameter(Mandatory=$True)]
	[string]
	$LabName    
    )

    # we need 2 sets of creds: 
    #  1 for the regular local account as defined in the system section of the xml
    #  2 for the built-in administrator account. This account needs to be enabled on the PDC as safe mode administrator.  
    $Pass = ConvertTo-SecureString $($domain.item("PDC_LocalPass")) -AsPlainText -Force
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential $($domain.item("PDC_LocalUser")),$pass
    $SafeModeAdminPassClearText = $($domain.item("SafeModeAdminPass"))
    $SafeModeAdminPass = ConvertTo-SecureString $($domain.item("SafeModeAdminPass")) -AsPlainText -Force
    $SafeModeAdminCreds = New-Object -TypeName System.Management.Automation.PSCredential "administrator",$SafeModeAdminPass
    
    # setting these variables so we can easy pass into scriptblock
    $NetUserString = "net user administrator $SafeModeAdminPassClearText /active:yes"
    $DomainName = $($domain.item("ADDSName"))

    Write-Verbose "[*] Starting Installation of ADDS Roles/Features"
    $Results = Invoke-Command -ComputerName $domain.item("PDC_IP") -Credential $Creds -ScriptBlock {
        # Installing the ADDS Roles
        install-windowsfeature AD-Domain-Services -IncludeManagementTools |Format-List exitcode,restartneeded
    }
     # Check if the previous command went ok.
    if($?) {
        Write-Verbose "[+] Successfully installed ADDS Roles/Features."
    } else { # command did not go ok
        Write-Error "[X] ERROR: could not install ADDS Roles/Features. Exiting."
        Break
    }
    
    Write-Verbose "[*] Enabling local administrator account"
    $Results = Invoke-Command -ComputerName $domain.item("PDC_IP") -Credential $creds -ScriptBlock { 
        param($NetUserString)
        #Enable local admin password - required by MSFT - Set-LocalUser and Enable-LocalUser arent availabel on all Windows Server versions
        cmd.exe /c "$NetUserString"
    } -ArgumentList $NetUserString
    # Check if the previous command went ok.
    if($?) { 
        Write-Verbose "[+] Local administrator account enabled."
    } else {
        Write-Warning "[!] WARNING: could not enable local administrator account. Trying to continue."
    }    

    # Install the Forest
    $Results = ""        
    Write-Verbose "[*] Installing the Forest - this may take several minutes"
    $Results = Invoke-Command -ComputerName $domain.item("PDC_IP") -Credential $creds -ScriptBlock { 
        param($Domainname,$SafeModeAdminPass)
        Install-ADDSForest -Force -DomainName $Domainname -SafeModeAdministratorPassword $SafeModeAdminPass | Format-List exitcode,restartneeded
    } -ArgumentList $Domainname,$SafeModeAdminPass
  
    # Check if the previous installation went ok.
    if($?) {
        # the computer just rebooted to finish the ADDS installation, giving it some time to come back before trying for 1st time.
        $TimeStart = Get-Date
        $TimeEnd = $timeStart.addminutes(5)
        $InstallOK = $False
        Write-Verbose "[*] PDC is rebooting for Forest and Domain to be effective. This can take a while depending on your hardware."
        Write-verbose "[*] We will wait up till 5 minutes, but check periodically."
        Start-Sleep -Seconds 60 
        while ((-not($InstallOK)) -and ($TimeEnd -ge $TimeStart) ) {
            if (Get-ADLabSystemUpStatus -ip $domain.item("PDC_IP") -username $domain.item("PDC_LocalUser") -password $domain.item("PDC_LocalPass") -timeout 15 ) {
                Write-Verbose "[+] PDC is back up. Now checking if ADDS is up and running."
                $Res = Invoke-Command -computername $domain.item("PDC_IP") -Credential $creds -ScriptBlock { (Get-CimInstance win32_computersystem).Domain }
                if ( $Res  = $DomainName )  { # install went ok
                   Start-Sleep -Seconds 30 # letting the PDC advertise itself on the network
                   Write-Verbose "[+] Forest and Domain $Domainname successfully installed."
                   $InstallOK = $True
                }
            }
            Start-Sleep -Seconds 30
        }
        if ($InstallOK = $false) { Write-Warning "[!] WARNING: ADDS installer ran, but couldn't evaluate the results of domain $DomainName."}    
    } else {Write-Error "[!] Error installing the Forest. More things will probably fail now."}

    #### Todo Add-DnsServerPrimaryZone -DynamicUpdate Secure -NetworkId ‘10.1.1.0/24’ -ReplicationScope Domain

} # end of function Invoke-ADLabInvokeADDS

Function Invoke-ADLabJoinDomain {
<#
    .Synopsis
       Join a domain

    .DESCRIPTION
      Function to join a system to a ADDS domain. 
          
    .EXAMPLE
      Invoke-ADLabJoinDOmain -Machine $VM -DomainAdminUsername "administrator" -DomainAdminPassword $($HTAdds.item($($VM.item("Domain"))).item("SafeModeAdminPass")) -DCname $($HTAdds.item($($VM.item("Domain"))).item("PDC"))

    .PARAMETER $Machine
        Hastable with info on the system we are joing to a domain - mandatory

    .PARAMETER $DomainAdminUsername
        String with the username of the domain admin account used for joing the domain - mandatory

    .PARAMETER $DomainAdminPassword
        String with the password of the domain admin account used for joing the domain - mandatory

    .PARAMETER $DCName
        String with the IP/hostname of the domain controller - mandatory

#>

    [CmdletBinding()]
    param (
    [Parameter(Mandatory = $True)]
	[hashtable]
	[ValidateNotNullOrEmpty()]
	$Machine,

    [Parameter(Mandatory=$True)]
    [string]
    $DomainAdminUsername,
    
    [Parameter(Mandatory=$True)]
    [string]
    $DomainAdminPassword,
    
    [Parameter(Mandatory = $True)]
    [string]
    $DCname        
    )

    $Pass = ConvertTo-SecureString $Machine.item("Pass") -AsPlainText -Force
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential $(".\"+$Machine.item("User")),$pass
    $DomainPass = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
    $DomainCreds = New-Object  -TypeName System.Management.Automation.PSCredential $($Machine.item("Domain")+"\"+$DomainAdminUsername),$DomainPass


    # Enable WinRM Service to start not delayed in the future
    Write-Verbose "[+] System $($Machine.item("Hostname")) : Enabling quick start of WinRM"
    Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock { cmd /c "sc config WinRM start= auto" } | Out-Null

    Write-verbose "[*] System $($Machine.item("Hostname")) : Starting domain join."
    # Check if domain joined, if not do so.
    $Results = Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock { (Get-WmiObject win32_computersystem).Domain }
    if (($?) -and ($results -eq $Machine.item("Domain"))){ 
        write-Verbose "[*] System $($Machine.item("Hostname")) : already in that domain. Nothing to do."
    } else { # command didnt go well or not in domain
        # Actually join the domain and reboot.
        Write-Verbose "[*] System $($Machine.item("Hostname")) : not joined, about to do so."
        Add-Computer -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -LocalCredential $Creds -DomainName $Machine.item("Domain") -Credential $DomainCreds -Restart -Force # -server $($DCname+"."+$Machine.item("Domain"))
        if (-not ($?)) { Write-Warning "[!] System $($Machine.item("Hostname")) WARNING: could not join domain $($Machine.item("Domain"))" } 
        else { # let the VM reboot for 60sec atfter joing the domain 
            Write-Verbose "[+] System $($Machine.item("Hostname")) : Successfully joined the domain. Now rebooting."
        } 
    }
} # end of function Invoke-ADLabJoinDomain

Function Invoke-ADLabSystemInstallSoftware {
<#
    .Synopsis
       Install local software packages

    .DESCRIPTION
      Function to install software packages on the local system.
          
    .EXAMPLE
      Invoke-ADLabSystemInstallSoftware -Machine $VM

    .PARAMETER $Machine
        Hastable with info on the system we are installing software on - mandatory

#>
    [CmdletBinding()]
    param (
    [Parameter(Mandatory = $True)]
	[hashtable]
	[ValidateNotNullOrEmpty()]
	$Machine       
    )
    
    $Pass = ConvertTo-SecureString $Machine.item("Pass") -AsPlainText -Force
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential $(".\"+$Machine.item("User")),$pass
    
    # Check if system is up and if we can log in
    if (-not(Get-ADLabSystemUpStatus -ip $($Machine.item("Net1_IP").split('/')[0]) -username $Machine.item("User") -password $Machine.item("Pass") -timeout 60)) { 
        Write-Warning "[!] system $($Machine.item("Hostname")) WARNING: system down or can't log in."
    }


    Write-verbose "[*] System $($Machine.item("Hostname")) : Starting package installations."
    
    # Disable bug in Customer Experience thingie that could make msi installs slow or even fail. 
    Write-Verbose "[+] System $($Machine.item("Hostname")) : Removing specific reg key of CEIP that is a known bug for slow msi installs."
    Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock { 
        if (Test-Path HKLM:\SOFTWARE\Microsoft\SQMClient\Windows\DisabledSessions) { cmd /c "reg delete HKLM\SOFTWARE\Microsoft\SQMClient\Windows\DisabledSessions /va /f"  }   
    } | Out-Null

    # stop spooler service as its known to casue slow Office installs - will be auto enabled after first reboot
    Write-Verbose "[+] System $($Machine.item("Hostname")) : Stopping Spooler service"
    Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock { cmd /c "sc stop spooler" } | Out-Null

    # Disable Volume Shadow copy for now - we will enable again later on
    Write-Verbose "[+] System $($Machine.item("Hostname")) : Disabling Volume Shadow Copy Service."
    Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock { cmd /c "sc config vss start= disabled" } |Out-Null

    # Install Software programs. 
    # We're copying the files to the local disk of the VM as some installers may need to write to dir where it is run from.
    # 
    # Couldnt get new-PSDrive to work reliable, so we are using copy-item directly. But copy-item cant work with creds. 
    # Solution is nasty trick to pre cache the creds by running old skool cmd command 'net use \\ip\c$ pass /user:username'.
    #
    $NetUseCmd = "`"net use \\"+$($Machine.item("Net1_IP").split('/')[0])+"\c`$ "+$Machine.item("Pass")+" /user:"+$Machine.item("User")+"`""
    & cmd /c $NetUseCmd | out-null    

    ## Install software - Just Copy files
    if ($Machine.item("SW_JustCopy")) {
        Write-Verbose "[*] System $($Machine.item("Hostname")) : Copying software files."
        foreach ($sw in $Machine.item("SW_JustCopy")) {
            Write-Verbose "[+] System $($Machine.item("Hostname")) : Copying software package $(($sw).split('\')[1]) "
            $SWPathSrc = $((Get-Item -Path ".\"-Verbose).FullName)+"\SoftwareInstallers\"+$sw
            $SWPathDest = "\\"+$($Machine.item("Net1_IP").split('/')[0])+"\C$\SoftwareInstallers\"
            New-item $SWPathDest -ItemType Directory -Force |Out-null
            Copy-Item "$SWPathSrc" -Destination "$SWPathDest" -Recurse -Force
        }
    } else {
        Write-Verbose "[*] System $($Machine.item("Hostname")) : No software files to copy."
    }

    ## Install software - run installers
    if ($Machine.item("SW_Install")) {
        Write-Verbose "[*] System $($Machine.item("Hostname")) : running msi software installers."
        foreach ($sw in $Machine.item("SW_Install")) {
            Write-Verbose "[+] System $($Machine.item("Hostname")) : Installing software package $(($sw).split('\')[1]). This may take some time. "
            $SWPathSrc = $((Get-Item -Path ".\"-Verbose).FullName)+"\SoftwareInstallers\"+$sw
            $SWPathDest = "\\"+$($Machine.item("Net1_IP").split('/')[0])+"\C$\SoftwareInstallers\"
            New-item $SWPathDest -ItemType Directory -Force |Out-null
            Copy-Item "$SWPathSrc" -Destination "$SWPathDest" -Recurse -Force
            $InstallString = "msiexec.exe /i C:\SoftwareInstallers\"+$(($sw).split('\')[1])+" /QN /L*V c:\SoftwareInstallers\sw-install-"+$(($sw).split('\')[1])+".log"
            Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $creds -ScriptBlock { 
                param($Installstring)
                & cmd /c $Installstring 
            } -ArgumentList $InstallString 
        }
    }

    ## Install Office
    if ($Machine.item("OfficeInstaller")) {
        $OfficePathSrc = $((Get-Item -Path ".\"-Verbose).FullName)+"\SoftwareInstallers\"+$($Machine.item("OfficeInstaller").split('\')[0])+"\"
        $OfficePathDest = "\\"+$($Machine.item("Net1_IP").split('/')[0])+"\C$\SoftwareInstallers\"

        # Setting the Office setup vars. I dont know why MSFT switched from /config to /configure with Office 2016, but it took me hours to realize.
        $OfficeSetup = "c:\SoftwareInstallers\"+$Machine.item("OfficeInstaller")
        if ( ($OfficePathSrc -like "*14*") -or ($OfficePathSrc -like "*15*") -or ($OfficePathSrc -like "*2010*") -or ($OfficePathSrc -like "*2013*") ) {
            $OfficeSetupArg = " /config c:\SoftwareInstallers\"+$Machine.item("OfficeConfig")
        } else {
            $OfficeSetupArg = " /configure c:\SoftwareInstallers\"+$Machine.item("OfficeConfig") 
        }

        Write-Verbose "[+] System $($Machine.item("Hostname")) : Copying Office installer files."
        New-item $OfficePathDest -ItemType Directory -Force |Out-null
        Copy-Item "$OfficePathSrc" -Destination "$OfficePathDest" -Recurse -Force
   
        # Starting the Office installer remotely
        Write-verbose "[*] System $($Machine.item("Hostname")) : Starting Office install. This may take some time."
        $Results = Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $creds -ScriptBlock { 
            param($OfficeSetup,$OfficeSetupArg,$InstallOK=$False)
            Start-Process -FilePath $OfficeSetup -ArgumentList $OfficeSetupArg -Verb runas -wait
            if ((Get-WmiObject -Class win32_operatingsystem).osarchitecture -match "32-bit") {
                $res = get-itemproperty hklm:\software\microsoft\windows\currentversion\uninstall\* | select DisplayName|where { $_.DisplayName -match “Office”}
                if ($res.count -ne 1) { 
                    $InstallOK = $True
                    #Get-ChildItem "C:\SoftwareInstallers\Office*" -Recurse | Remove-Item -Force
                    rm -r  -fo "C:\SoftwareInstallers\Office*"
                }
            } else {
                $res = get-itemproperty hklm:\software\wow6432node\microsoft\windows\currentversion\uninstall\* | select DisplayName|where { $_.DisplayName -match “Office”}
                if ($res.count -ne 1) { 
                    $InstallOK = $True
                    #Get-ChildItem "C:\SoftwareInstallers\Office*" -Recurse | Remove-Item -Force
                    rm -r  -fo "C:\SoftwareInstallers\Office*"
                }
            }
            Return $InstallOK
        } -ArgumentList $OfficeSetup,$OfficeSetupArg 
 
        if ($Results) { 
            Write-verbose "[+] System $($Machine.item("Hostname")) : Office installation successful." 
        } else {  
            Write-Warning "[!] System $($Machine.item("Hostname")) : Office installation not successful."
        }
    } else {
        Write-Verbose "[*] System $($Machine.item("Hostname")) : No Office to install."
    }

    # Enable Volume Shadow copy back to manual state
    Write-Verbose "[+] System $($Machine.item("Hostname")) : Enabling Volume Shadow Copy Service."
    Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock { cmd /c "sc config vss start= manual" } |Out-Null

    # removing the 'net use' drive mapping
    $NetUseCmd = "`"net use \\"+$($Machine.item("Net1_IP").split('/')[0])+"\c`$ /delete`""
    & cmd /c $NetUseCmd | out-null    

    Write-Verbose "[*] System $($Machine.item("Hostname")) : Done with software installation on this system."       
} # end of function Invoke-ADLabSystemInstallSoftware

Function Invoke-ADLabSystemLocalConfig {
<#
    .Synopsis
       Perform local system configurations

    .DESCRIPTION
      Function to perform local configurations on the system.
          
    .EXAMPLE
      Invoke-ADLabSystemLocalConfig -Machine $VM 

    .PARAMETER $Machine
        Hastable with info on the system we are installing software on - mandatory

#>
    [CmdletBinding()]
    param (
    [Parameter(Mandatory = $True)]
	[hashtable]
	[ValidateNotNullOrEmpty()]
	$Machine,

    [Parameter(Mandatory=$False)]
    [string]
    $DomainUsername,
    
    [Parameter(Mandatory=$False)]
    [string]
    $DomainUserPass      
    )
    
    $Pass = ConvertTo-SecureString $Machine.item("Pass") -AsPlainText -Force
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential $(".\"+$Machine.item("User")),$pass

    Write-verbose "[*] System $($Machine.item("Hostname")) : Starting local configurations."

    $IsDomainJoined = $False

    # Verify if we need to do domain related actions
    if ($vm.ContainsKey("Domain")) {
        Write-verbose "[*] System $($Machine.item("Hostname")) : Running with domain creds - will do domain related local tasks."
        $IsDomainJoined = $True
    }

    # Check if system is up and if we can log in
    if (-not(Get-ADLabSystemUpStatus -ip $($Machine.item("Net1_IP").split('/')[0]) -username $Machine.item("User") -password $Machine.item("Pass") -timeout 60)) { 
        Write-Warning "[!] system $($Machine.item("Hostname")) WARNING: system down or can't log in."
    }

    # Setting RDP stuff
    Write-verbose "[*] System $($Machine.item("Hostname")) : Setting RDP settings."
    if ($Machine.item("RDP_Allow") -match "True" ) {
        Write-verbose "[+] System $($Machine.item("Hostname")) : Enabling RDP."
        Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock {  
            cmd /c 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f' | Out-Null
        }
        if ($IsDomainJoined) {
            Write-verbose "[+] System $($Machine.item("Hostname")) : Allowing 'Domain users' group to RDP."
            Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock {  
                cmd /c 'net localgroup "Remote Desktop Users" "Domain Users" /add' | Out-Null
            }
        }
    }
      
    # Disable Restore Point making - only available on client OSes
    if ($($Machine.item("Type")) -like "Client") {
    	Write-Verbose "[+] System $($Machine.item("Hostname")) : Disabling Restore Points."
        Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock { Disable-ComputerRestore -Drive "c:\" } | Out-Null
	}  

    # Setting windows update settings according to lab config file - by default disabled 
    if ($Machine.item("Win_Update") -and ($Machine.item("Win_Update") -match "True")) {
        Write-Verbose "[+] System $($Machine.item("Hostname")) : Setting Windows Update settings to Auto-Update"
        Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock { 
            # Setting registry keys in policies subdir
            New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
            New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
            New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\" -Name NoAutoUpdate -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
            New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\" -Name AUOptions -Value 4 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
            New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\" -Name ScheduledInstallDay -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
            New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\" -Name ScheduledInstallTime -Value 8 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
            New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\" -Name NoAutoRebootWithLoggedOnUsers -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
            # restarting auto update service and make sure it auto starts
            cmd /c 'net stop wuauserv > nul 2> nul' # redirect error out as the service may already be stopped, causing to prompt an error
            cmd /c 'net start wuauserv > nul 2>nul'
            cmd /c 'sc config wuauserv start= auto'
        } | Out-NUll
        # Windows 10 and Server 2016 have different commands for forcing checks of updates
        if ( ($Machine.item("OS") -like "*indows2016*") -or ($Machine.item("OS") -like "*indows10*") ) {
            Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock {
                cmd /c 'UsoClient.exe ScanInstallWait'
            }
        } else {
            Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock {
                cmd /c 'wuauclt.exe /checknow'
                cmd /c 'wuauclt.exe /updatenow'
            }
        }            
    } else {
        Invoke-Command -ComputerName $($Machine.item("Net1_IP").split('/')[0]) -Credential $Creds -ScriptBlock {
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name AUOptions -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name NoAutoUpdate -Value 2 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
            cmd /c 'sc config wuauserv start= disabled'
        } |Out-Null
    }

    Write-Verbose "[*] System $($Machine.item("Hostname")) : Done with local configurations."       
} # end of function Invoke-ADLabSystemLocalConfig