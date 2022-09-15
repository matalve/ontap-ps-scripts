$AllDevices = Get-WmiObject -Class Win32_DiskDrive -Namespace 'root\CIMV2'
ForEach ($Device in $AllDevices) {
	if($Device.Model -like 'NETAPP LUN*') {
		@{
			Name=$Device.Name;
			Caption=$Device.Caption;
			Index=$Device.Index;
			Size_GB=$Device.Size/1024/1024/1024
			SerialNo=$Device.SerialNumber;
		} | Format-Table -AutoSize
	}
}
