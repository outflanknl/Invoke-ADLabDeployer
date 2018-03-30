# Goal of the project #
Automated deployment of Windows and Active Directory test lab networks. Useful for red and blue teams.

During red teaming gigs we encounter many different setups at our clients. To test our payloads and to review our artefacts we need a lab that allows us to quickly deploy Windows OS version X with Office version Y, in a fully working AD and a network setup that has separate broadcast segments. 
Invoke-ADLabDeployer does the heavy lifting. From there on you can easily tune to your exact liking, e.g. create specific GPO’s, install extra software, and make any other final tuning for the setup that you need. 

Invoke-ADLabDeployer relies heavily on techniques like Hyper-V, sysprep and (remote) Powershell for the deployment and configuration.

There are other projects out there that do similar things. But Invoke-ADLabDeployer has support for all Windows OS versions currently encountered at clients, specifically support for Win7 and Server2008R2, while keeping resource usage low by using smart Hyper-V tricks like differencing disks, dynamic memory, etc.
More background info and reasoning why this script has added value over others as well as over Azure [here](https://outflank.nl/blog/2018/03/30/automated-ad-and-windows-test-lab-deployments-with-invoke-adlabdeployer/)

## Running the script ##
**There is no quick starting with this script. You really need to have parent images pre-created.**

If you are sure you meet all the requirements and have done all the preparations, you can run it using:

Import: `Import-Module .\Invoke-ADLabDeployer.ps1`

Start deployment: `Invoke-ADLabDeployer -LabConfigFile configs\labs_config.xml -Name demolab -Verbose`

The `-Verbose` tag will give you handy status reports.

Example output can be found [here](./Invoke-ADLabDeployer_consoleoutput_fullrun.txt).


Test the config file: `Invoke-ADLabDeployer -LabConfigFile configs\labs_config.xml -Name demolab -CheckConfigOnly`

Have the config returned into local hashtables: `$return_net,$return_sys,$return_adds = Invoke-ADLabDeployer -LabConfigFile configs\labs_config.xml -Name demolab -CheckConfigOnly`

Example output can be found [here](./Invoke-ADLabDeployer_consoleoutput_CheckConfigOnly.txt)


## Flow of script ##
On a generic level, the following tasks are performed:
- Read the configuration file and perform syntax checks
- Basic check on host OS network setup, i.e. required packages, enable routing and set WSMan trustedhosts
- Virtual network setup.
- Make linked copies (differencing disks) to the parent VHDs.
- Mount the linked disks and edit the unattend file to inject hostname, IP address, local user, etc. 
- Unmount the disks and create the new virtual guests from the linked VHDs.
- Power on, wait some time for sysprep to complete.
- Install and configure the Active Directory Domain Controller.
- Have clients join the new domain.
- Install Office and other software packages.
- Perform final configs of local settings, e.g. RDP, Windows Update, some performance tuning, etc.



## Requirements ##
You need the following:
- Required licenses for Microsoft software you are deploying. We use our own licenses. To get you started quickly, Ive included evaluation license keys in the Windows unattend files. The Office unattend files have "XXX" as license key, so you need to change that to be able to install Office. The Windows license keys are [EVAL licenses](https://docs.microsoft.com/en-us/windows-server/get-started/kmsclientkeys) and should work on all Windows versions whatever the install ISO is. There is one exception: 2008R2. The 2008R2 setup installer is very picky on the exact install ISO you used. The supplied license in the unattend file is for en_windows_server_2008_r2_with_sp1_vl_build_x64_dvd_617403.iso **You may or may not be in violation with Microsoft license agreements. Use at your own risk.**
- Local server that is capable of running multiple virtual machines. Intel VT-x or AMD/V capable CPU and a SSD disk is highly recommended. I'm using an Intel Skull NUC, solely for this purpose. It runs perfect and is able to deploy and host dozens of systems.
- A base Windows server OS that will host the lab using Hyper-V. Im running Server 2016. While I believe this will also work on other systems while WMF 5.0 is installed, I have not tested this.
- Parent images: virtual hard drives with the parent images prepared of what you want to deploy. Ive got Win7, Win8.1, Win10, 2016 LTSB, Win10 1709, Server 2008r2, 2012R2 and 2016. For each desktop OS I have a x86 and an x64 version, servers just x64 but there is no reason why x86 shouldn't work. More info on this below. The systems need to run powershell 2.0. So in theory it could also deploy Windows XP and 2003, but this is not tested.
- Config file: a XML file that defines the layout of the lab that you want to deploy. More info on this below.
- As the lab will dohave multiple subnets, we need to have RRAS (Routing and Remote Access) service installed, and the routing package. But they dont need to be configured as you would normally do, the script does this for you. This is probably against MSFT guidelines, but it works. The script does some checking and will help you to some degree with this. But if you encounter any issues, run Install-WindowsFeature RSAT-RemoteAccess –IncludeManagementTools; Install-WindowsFeature Routing -IncludeManagementTools
- Base installation files for the Office versions if you want to install Office. This repository includes config files for unattended Office installs. You do need to add your own license key, and perhaps go through the exact Office applications you want to install as defined in the office config files.


## Creating the parent images ##
- Create a new virtual machine in Hyper-V as you normally would. Have the disk stored in the `\disks\parentdsisks\` directory. Generation 2 virtual machines are preferred, but Hyper-V only supports this if 64bit desktop OS is Win8 or later, or server OS is win2012 or later (32 and 64bit). More info [here](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/should-i-create-a-generation-1-or-2-virtual-machine-in-hyper-v#BKMK_Windows)
- Power on, install Windows and update to the level you want. 
- Post install **required** changes:
  - Enable WSMan: in powershell: `Set-WsManQuickConfig -Force`
  - Enable RemotePowershell: in powershell: `Enable-PSRemoting -Force`
  - Reset the NIC connection profile setting: in powershell: `$NLMType = [Type]::GetTypeFromCLSID('DCB00C01-570F-4A9B-8D69-199FDBA5723B');$INetworkListManager = [Activator]::CreateInstance($NLMType);$INetworks = $INetworkListManager.GetNetworks(1);foreach ($INetwork in $INetworks) { $INetwork.SetCategory(0x01) } `
    this sets the connection profile to Private in a powershell version that Win7 also can handle.
  - Disable the firewall: in a command prompt: `netsh advfirewall set allprofiles state off`
- _Optional:_ you can poweroff and make a backup of the vhd if you want. I recommend this as it makes troubleshooting and restoring after sysprep issues easier.
- Copy the `unattend_regularboot.xml` file for that OS version to the guest. 
- Start sysprep: `cmd: c:\windows\system32\sysprep\sysprep.exe /generalize /oobe /shutdown /unattend:c:\unattend_regularboot.xml`
- Recommended: boot the system once to test sysprep finalises OK. In case of any error, I recommend to poweroff the machine and mount the disk using your host machine. This allows for easier debugging of sysprep images. You want to check `c:\windows\panther\UnattendGC\setuperror.log` for troubleshooting. You can easily check that file by simply mounting the vhd of the guest vm.
- **Important**: the parent image needs to be in a sysprepped and powerd off state. So if you did a test run to see if sysprep worked ok, make sure to power if off again using the sysprep command with the ‘regularboot’ unattend file.


## Lab config file ##
The script needs a config file to know what it needs to deploy. Ive included an example lab_config.xml file. It should be rather self explanatory, but you can find more detailed info below.

The config file can have multiple labs defined. The `-Name` parameter to Invoke-ADLabDeployer defines the actual lab to deploy. Also, the `-CheckConfigOnly` parameter can help you with, well, checking the config. Per lab name you define the other sections you can find below. But on a general level you can have a config like:
```
<Labs>
	<Lab LabName="TestLab">
	</Lab>
	<Lab LabName="OtherTestLab">
	</Lab>	
	<Lab LabName="FooBar">
	</Lab>	
</Labs> 
```
### Config file parameters - Network ###
This defined the network sections. This is mandatory. You can have multiple sections of this.
Example:
```
<Network NetName="net1">
	<Subnet>10.202.1.0/24</Subnet>
	<GW>10.202.1.1</GW>
</Network>
```
- `NetName`: the name
- `Subnet`: network address of the subnet, requires a subnet mask defintion in form of `/XX`
- `GW`: IP address of the gateway of this subnet. The virtual switch on your host system will get this address. 

### Config file parameters - Active Directory ###
This defines the Active Directory section. This is not mandatory. You can have multiple sections of this.
Example:
```
<ADDS ADDSName="BreakMe.local">
	<ParentDomain>.</ParentDomain>
	<PDC>server1</PDC>
	<SafeModeAdminPass>Outflank123</SafeModeAdminPass>
</ADDS>
```
- _Optional_ `ParentDomain`: doesnt do anything at this moment
- `ADDSName`: the name
- `PDC`: the name of the system that will be the first domain controller. This name needs to correspond with a Hostname in the `System` section.
- `SafeModeAdminPass`: password required by Active Directory as the safe mode password for the local administrator account.


### Config file parameters - System ###
This defines a system. This is mandatory. You can have multiple sections of this.
Example:
```
<System Hostname="server1">
	<OS>windows2012R2x64</OS>
	<UnattendFile>unattend\unattend.win2012R2.xml</UnattendFile>
	<LocalCreds>outflank:Outflank123</LocalCreds>
	<ParentDisk>parent-en_windows_server_2012_r2_essentials_with_update_x64_dvd_6052824-updated201704</ParentDisk>
	<Net1_Name>net1</Net1_Name>
	<Net1_IP>10.202.1.11/24</Net1_IP>
</System>
<System Hostname="client3">
	<OS>windows7x64</OS>
	<UnattendFile>unattend\unattend.win7.xml</UnattendFile>
	<LocalCreds>ted:Outflank123</LocalCreds>
	<ParentDisk>parent-en_windows_7_enterprise_n_with_sp1_x64_dvd_u_677704-updated201801</ParentDisk>
	<Net1_Name>net2</Net1_Name>
	<Net1_IP>10.202.2.13/24</Net1_IP>
	<Mem>4GB</Mem>
	<Win_Update>True</Win_Update> 
	<Domain>BreakMe.local</Domain>
	<RDP_Allow>True</RDP_Allow>	
	<OfficeInstaller>Office16x64\setup.exe</OfficeInstaller>
	<OfficeConfig>Office16x64\config.xml</OfficeConfig>
	<SW_JustCopy>somefile.bin</SW_JustCopy>	
	<SW_Install>Chrome\googlechromestandaloneenterprise.msi</SW_Install>
	<SW_Install>7z\7z1801-x86.msi</SW_Install>
	<SW_Install>npp\npp.7.5.0.installer.x86.msi</SW_Install>			
</System>
```
- `Hostname`: the hostname
- `OS`: Specific Windows version of the system. Allowed values at this moment are: 
  - `Windows7x86`
  - `Windows7x64`
  - `Windows8.1x86`
  - `Windows8.1x64`
  - `Windows10x86`
  - `Windows10x64`
  - `Windows2008R2x64`
  - `Windows2012R2x64`
  - `Windows2016x64`
- `UnattendFile`: the path of the unattend file
- `LocalCred`: username:password of a local administrator account. 
- `ParentDisk`: the filename of the parent image VHD disk. ".VHDX" is automatically added.
- `Net1_Name`: the name of the network as defined in the Network section.
- `Net1_IP`: the IP address+subnet mask you give to this host.
- _optional_ `Mem`: the amount of memory you want the system to have. If not specified, server OSes will get 1GB and client OSes will get 2GB.
- _optional_ `Net1_GW`: manually define a default gateway for this NIC. This will not influence the setup of the virtual network, only the deployed system's routing table. So unless you've manually created a router somewhere, this parameter will likely break routing for this system.
- _optional_ `SkipDeploy`: set to `True` if you do not want this system to be deployed but still keep its config in the config file. 
- _optional_ `Net1_DNS`: The DNS server address you want this machine to have. If not set, it will pick the IP address of the PDC if the system is domain joined, or 9.9.9.9 for non domain joined machines. If you want 2 DNS servers configured, make them comma separated.
- _optional_ `Domain`: the Active Directory domain name to join as defined in the ADDS section.
- _optional_ `RDP_Allow`: When set to `True` RDP will be enabled. Also, the local users group, and domain users if domain joined, are added to the 'Remote Desktop Users' group.
- _optional_ `OfficeInstaller`: path to Office installer executable. Also requires OfficeConfig to be set.
- _optional_ `OfficeConfig`: path to the office config file. Also requires OfficeInstaller to be set.
- _optional_ `SW_JustCopy`: path to a file you just want to be copied. Can be multiple. Will be copied to c:\SoftwareInstallers.
- _optional_ `SW_Install`: path to a msi installer file that you want to be installed. Can be multiple. A log of the msiexec installation output is placed in c:\SoftwareInstallers.


## Directory structure ##
This repo and script uses the following directory structure, which is recommended to adhere to as some paths may be hardcoded:
- `.\configs`: here are lab config files
- `.\configs\unattend\`: here are the unattend files
- `.\disks`: the VHDs of your deployed lab be put in a subdirectory per labname.
- `.\disks\parentdisks\`: here you need to store the parent VHDs.
- `.\SoftwareInstallers`: home for extra software packages that you want to deploy.
- `.\SoftwareInstallers\Office14x86\`: example of Office folder, in this folder is the config.xml and the setup binary - basically just copy the entire contents of the install ISO to this folder.


## Known bugs and caveats ##
- You need to prepare the base images yourself, this script does not do this for you. Im open for ideas to automate this.
- Only supports English versions of Windows. Main reason is hardcoded commands like 'net localgroup "Remote Desktop Users"'. This is a result of a design choice to support systems with that only run PowerShell v2. Later PowerShell versions have fancy commands to alter local groups, but v2 doesnt. This is likely not going change in future versions, unless there is a way to keep support for PowerShell v2.
- The server OS unattend files in this repository do not have support for 32 bit versions. This is not a hard change to do as it only required x86 sections of settings in the unattend files. I simply havent had the time nor demand for it.
- Error and state checking is not really structured. If a system can't complete a specific task its simply reported in the output, but the script continues with its flow. Depending tasks will fail as well.
- Timeouts are tuned to my hardware. If you have slower hardware (or deploy huge networks) its possible deployment will not go as smooth as hoped. 
- The script makes use of native routing instead of NAT on the Hyper-V host. This is an explicit choice as it allows you to remotely connect to the deployed guests using their lab IP address from any other remote system. However, unless your Hyper-V machine is also your core router, or unless you only connect to your deployed guests from your Hyper-V machine, your network might not know how to reach the deployed subnet. Depending on your network setup, this may also prevent your lab systems from reaching the internet. There is an easy fix for this: manual static routes on your core router pointing to the deployed subnets. Reading this line of text takes longer than setting the static route in your network.
- XML tags are case sensitive. If the config check fails, check the case of the tags in your config file.
- System computername can't exceed 15 characters and can't contain dots. This is a native Windows issue that I cant fix, but I just want to warn you as you may encounter this.
- Server 2008(R2) can't be running the PDC. There are no Powershell commands for this, so this would need dcpromo commands in order to work. But this is a very specific situation that I haven't seen in a live environment anymore in years. 2008R2 Can install the mngt tools using `Import-Module Servermanager; Add-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature` but the initial domain still needs to be done using dcpromo.
- Auto updates, if configured using the `<Win_Update>` tag, may start many hours after your deployment. Im open to ideas for instant deployment that works on all Windows vesions.
- Auto updates on some 2012R2 (and up) and 8.1 (and up) versions don't seem to work completely. They require you to manually hit 'check for updates now' inside the guest the 1st time.
- The progress bar of the installation of Active Directory Domain Services keeps on top even after successful installation of ADDS; it never finishes.


## Features on todo-list ##
- Windows 10: disable background scanning of defender, defrag etc to safe CPU resources when idle.
- Windows 10: control detailed Defender settings from config file.
- Have a function for automated monthly updates of the base images. This is about 80% done.
- Automate the installation of sysmon+WEC+ELK per lab. This is about 50% done.
- Incremental updates of deployed labs: have the script check if a lab already exists, and if so let it check if there are hosts in the new config that arent deployed yet and only deploy these.
- Support for AD subdomains, domains in same forest and domains in separate forests.
- Add users, groups, OU to the AD domain based on an input file. This is about 50% done.
- Include 32bit support in the unattend files for server Windows versions.
- make IP address of system optional: have the script auto pick an IP address in the network.
- Support for multiple NICs per system.
- More advanced networking setup, where lab config file can be used to determine detailed routing setup. Preferably using true Hyper-V Network Virtualization (RRIDs, CA, PA, etc.).


## Author ##
This project is developed and maintained by Marc Smeets (@smeetsie on github, and @mramsmeets on Twitter). 

## License ##
This project is made available uner the BSD 3.0 license. This means:
Copyright 2018 Outflank B.V.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
