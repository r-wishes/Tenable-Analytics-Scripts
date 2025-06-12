function Invoke-AnalyticsReport {

    <#
            .SYNOPSIS
            Creates an analytics report for Tenable authenticated scan (not suitable for vulnerabilities search export).
    
            .DESCRIPTION
            Parses Nessus scan CSV exports to identify authentication results per IP, such as whether each IP has plugins: "Valid Credentials Provided" (141118), "Failure for Provided Credentials" (104410), "Nessus Scan Information" (19506). Additionally, uses "OS Identification" (11936) to list the host's OS and attempts to identify the succeeded username, if any. Optional functionalities described in parameters.
    
            .PARAMETER InputCsvPath
            Specifies the scan export file name (.csv).
    
            .PARAMETER OutputCsvName
            Specifies the analytics report file name (.csv). By default appends "-analytics" to the original file name.
    
            .PARAMETER ExcludeScanName
            Excludes Scan Name column.
    
            .PARAMETER ExcludeScannerIP
            Excludes Scanner IP column.
    
            .PARAMETER CheckPluginsPresence
            Accepts comma-separated integer Plugin IDs. Adds columns for each Plugin ID provided, checking whether the plugins are present for IPs. Example: -CheckPluginsPresence 102094,14272
    
            .PARAMETER PluginNamesHashTable
            Used with CheckPluginsPresence. Accepts a PowerShell HashTable object, where keys are Plugin IDs (integer type), and values are the corresponding column names (string type). Expects column names defined for each Plugin ID provided in CheckPluginsPresence. Use carefully.
    
            .PARAMETER SaveExportWithNoInfoPlugins
            Deletes Info plugins and saves the rest in a separate file, appending "-no-info-plugins" to the original file name.
    
            .PARAMETER EnableFortiDeviceDetection
            Works if Fortinet devices are in scope. Uses plugin "Fortinet Device Detection" (73522) to add columns "Forti model" and "Forti version" to the report.
    
            .INPUTS
            None. You can't pipe objects to Invoke-AnalyticsReport.
    
            .OUTPUTS
            Analytics report file (.csv). Optionally: plugins export file with no info plugins (.cvs).
    
            .EXAMPLE
            PS> Invoke-AnalyticsReport -InputCsvPath vulns.csv
    
            .EXAMPLE
            PS> Invoke-AnalyticsReport -InputCsvPath vulns.csv -OutputCsvName report.csv
    
            .EXAMPLE
            PS> Invoke-AnalyticsReport -InputCsvPath vulns.csv -OutputCsvName report.csv
    
            .EXAMPLE
            PS> Invoke-AnalyticsReport -InputCsvPath vulns.csv -OutputCsvName report.csv -SaveExportWithNoInfoPlugins -EnableFortiDeviceDetection -ExcludeScanName
    
            .EXAMPLE
            PS> Invoke-AnalyticsReport -InputCsvPath vulns.csv -CheckPluginsPresence 102094 -PluginNamesHashTable @{102094 = "Privs Issue"} -SaveExportWithNoInfoPlugins
    
    #>
    
    param (
        [Parameter(mandatory = $true)]
        [string]$InputCsvPath,
        [Parameter(mandatory = $false)]
        [string]$OutputCsvName,
        [Parameter(mandatory = $false)]
        [switch]$ExcludeScanName,
        [Parameter(mandatory = $false)]
        [int[]]$CheckPluginsPresence,
        [Parameter(mandatory = $false)]
        [hashtable]$PluginNamesHashTable,
        [Parameter(mandatory = $false)]
        [switch]$SaveExportWithNoInfoPlugins,
        [Parameter(mandatory = $false)]
        [switch]$EnableFortiDeviceDetection
    )

    $plugin_id_column_name_sc = "Plugin ID"
    $plugin_id_column_name_tvm = "Plugin"
    $plugin_id_column_name = ""
    $plugin_name_column_name = "Plugin Name"
    $ip_address_column_name = "IP Address"
    $plugin_output_column_name = "Plugin Output"
    $severity_column_name = "Severity"
    $info_severity_value = "Info"
    $scan_info_plugin_id = "19506"
    $ping_status_plugin_id = "10180"
    $creds_valid_plugin_id = "141118"
    $creds_failure_plugin_id = "104410"
    $os_identification_plugin_id = "11936"
    $fortinet_device_detection_plugin_id = "73522"

    
    $input_csv_path = $InputCsvPath
    
    Write-Output "Analyzing file $($input_csv_path)"
    
    $input_csv_file = Get-Item $input_csv_path
    $scan_csv = Import-Csv -Path $input_csv_path
    
    Write-Output "CSV imported"
    
    if ($scan_csv[0].PSObject.Properties.Name -contains $plugin_id_column_name_sc) {
        $plugin_id_column_name = $plugin_id_column_name_sc
    }
    elseif ($scan_csv[0].PSObject.Properties.Name -contains $plugin_id_column_name_tvm) {
        $plugin_id_column_name = $plugin_id_column_name_tvm
    }
    else {
        Write-Output "Warning: No Plugin / Plugin ID column found. Exiting..."
        return -1
    }
    
    $unique_ips = $scan_csv | Select-Object -Property $ip_address_column_name -Unique
    $scan_info = $scan_csv | Select-Object -Property $plugin_id_column_name, $plugin_name_column_name, $ip_address_column_name, $plugin_output_column_name | Where-Object -Property $plugin_id_column_name -Like $scan_info_plugin_id
    $cred_checks_yes = ($scan_info | Where-Object -Property $plugin_output_column_name -Like '*Credentialed checks : yes,*').$ip_address_column_name
    $ping_status = $scan_csv | Select-Object -Property $plugin_id_column_name, $plugin_name_column_name, $ip_address_column_name, $plugin_output_column_name | Where-Object -Property $plugin_id_column_name -Like $ping_status_plugin_id
    $creds_valid = $scan_csv | Select-Object -Property $plugin_id_column_name, $plugin_name_column_name, $ip_address_column_name, $plugin_output_column_name | Where-Object -Property $plugin_id_column_name -Like $creds_valid_plugin_id
    $creds_failure = $scan_csv | Select-Object -Property $plugin_id_column_name, $plugin_name_column_name, $ip_address_column_name | Where-Object -Property $plugin_id_column_name -Like $creds_failure_plugin_id
    $os_identification = $scan_csv | Select-Object -Property $plugin_id_column_name, $plugin_name_column_name, $ip_address_column_name, $plugin_output_column_name | Where-Object -Property $plugin_id_column_name -Like $os_identification_plugin_id
    $forti_device_identification = @()
    if ($EnableFortiDeviceDetection) {
        $forti_device_identification = $scan_csv | Select-Object -Property $plugin_id_column_name, $plugin_name_column_name, $ip_address_column_name, $plugin_output_column_name | Where-Object -Property $plugin_id_column_name -Like $fortinet_device_detection_plugin_id
    }
    
    Write-Output "Plugins lists created"
    
    if ($CheckPluginsPresence) {
        Write-Output "The following additional plugin checks will be added: $($CheckPluginsPresence -join ', ')"
    }
    
    if ($PluginNamesHashTable -and $CheckPluginsPresence) {
        foreach ($plugin_id in $PluginNamesHashTable.Keys) {
            if ( !($plugin_id -is [int]) ) {
                Write-Output "Warning: HashTable Key $($plugin_id) is not a valid Plugin ID (integer) and will not be mapped with CheckPluginsPresence values"
            }
            if ( !($PluginNamesHashTable[$plugin_id] -is [string]) ) {
                Write-Output "Warning: HashTable Value found by key $($plugin_id) is not a valid Plugin Name (string). Exiting..."
                return -1
            }
        }
        Write-Output "The following additional columns will be added:"
        foreach ($plugin_id in $CheckPluginsPresence) {
            if (($plugin_id -in $PluginNamesHashTable.Keys) -and ($PluginNamesHashTable[$plugin_id])) {
                Write-Output "Column '$($PluginNamesHashTable[$plugin_id])' for Plugin ID $($plugin_id)"
            }
            else {
                Write-Output "Warning: Plugin ID $($plugin_id) is not found in the PluginNamesHashTable keys. Plugin ID will be added as column name."
            }
        }
    }
    
    if ($PluginNamesHashTable -and !$CheckPluginsPresence) {
        Write-Output "CheckPluginsPresence parameter not found, skipping PluginNamesHashTable"
    }
    
    $ips_count = $unique_ips.Count
    $current_index = 0
    $report_delta = [int]($ips_count / 10)
    $next_report_index = $report_delta
    
    Write-Output "Starting processing $($ips_count) unique IPs"
    
    $report_ips = @()
    
    foreach ($ip_line in $unique_ips) {
        if ($current_index -eq $next_report_index) {
            Write-Output "Processing $($current_index)/$($ips_count) IPs"
            $next_report_index += $report_delta
        }
        $ip = $ip_line.$ip_address_column_name
        $is_creds_valid = $ip -in $creds_valid.$ip_address_column_name
        $user_by_creds_valid = ""
        $port_by_creds_valid = ""
        $proto_by_creds_valid = ""
        $method_by_creds_valid = ""
        $source_by_creds_valid = ""
        $escalation_by_creds_valid = ""
        if ($is_creds_valid) {
            $plugin_output_lines = ($creds_valid | Where-Object -Property $ip_address_column_name -Like $ip).$plugin_output_column_name -split "`r?`n"
            if ($user_line = $plugin_output_lines | Select-String -Pattern 'User:*') { $user_by_creds_valid = ($user_line -split "'")[1] }
            if ($port_line = $plugin_output_lines | Select-String -Pattern 'Port:*') { $port_by_creds_valid = (($port_line -split ":")[1]).Trim() }
            if ($proto_line = $plugin_output_lines | Select-String -Pattern 'Proto:*') { $proto_by_creds_valid = (($proto_line -split ":")[1]).Trim() }
            if ($method_line = $plugin_output_lines | Select-String -Pattern 'Method:*') { $method_by_creds_valid = (($method_line -split ":")[1]).Trim() }
            if ($source_line = $plugin_output_lines | Select-String -Pattern 'Source:*') { $source_by_creds_valid = (($source_line -split ":")[1]).Trim() }
            if ($escalation_line = $plugin_output_lines | Select-String -Pattern 'Escalation:*') { $escalation_by_creds_valid = (($escalation_line -split ":")[1]).Trim() }
        }
        $is_creds_failure = $ip -in $creds_failure.$ip_address_column_name
        $os = ""
        $plugin_output_lines = ($os_identification | Where-Object -Property $ip_address_column_name -Like $ip).$plugin_output_column_name -split "`r?`n"
        if ($os_line = $plugin_output_lines | Select-String -Pattern 'Remote operating system : *') { $os = ($os_line -split ":")[1].Trim() }
        $forti_model = ""
        $forti_version = ""
        if ($EnableFortiDeviceDetection) {
            $plugin_output_lines = ($forti_device_identification | Where-Object -Property $ip_address_column_name -Like $ip).$plugin_output_column_name -split "`r?`n"
            if ($forti_model_line = $plugin_output_lines | Select-String -Pattern 'Model +:') { $forti_model = ($forti_model_line -split ":")[1].Trim() }
            if ($forti_version_line = $plugin_output_lines | Select-String -Pattern 'Version +:') { $forti_version = ($forti_version_line -split ":")[1].Trim() }
        }
        $is_credentialed = $ip -in $cred_checks_yes
        if ($is_credentialed) {
            $user_by_nessus_scan_info = ((($scan_info | Where-Object -Property $ip_address_column_name -Like $ip).$plugin_output_column_name -split "`r?`n" | Select-String -Pattern 'Credentialed checks : yes,*') -split "'")[1]
        }
        else {
            $user_by_nessus_scan_info = ""
        }
        $ping_status_value = ""
        if ($ip -in $ping_status.$ip_address_column_name) {
            $ping_status_value = ((($ping_status | Where-Object -Property $ip_address_column_name -Like $ip).$plugin_output_column_name -split "`r?`n" | Select-String -Pattern 'The remote host is ') -split "The remote host is ")[1]
        }
        if (!$ExcludeScanName) {
            $scan_name_by_nessus_scan_info = ((($scan_info | Where-Object -Property $ip_address_column_name -Like $ip).$plugin_output_column_name -split "`r?`n" | Select-String -Pattern 'Scan Name : ') -split "Scan name : ")[1]
        }
        else {
            $scan_name_by_nessus_scan_info = ""
        }
        if (!$ExcludeScannerIP) {
            $scanner_ip_by_nessus_scan_info = ((($scan_info | Where-Object -Property $ip_address_column_name -Like $ip).$plugin_output_column_name -split "`r?`n" | Select-String -Pattern 'Scanner IP : ') -split "Scanner IP : ")[1]
        }
        else {
            $scanner_ip_by_nessus_scan_info = ""
        }
    
        $row = [PSCustomObject]@{
            IP                          = $ip
            "Ping Status"               = $ping_status_value
            "Creds valid"               = $is_creds_valid
            "Creds failure"             = $is_creds_failure
            "User by Creds valid"       = $user_by_creds_valid
            "Port by Creds valid"       = $port_by_creds_valid
            "Proto by Creds valid"      = $proto_by_creds_valid
            "Method by Creds valid"     = $method_by_creds_valid
            "Source by Creds valid"     = $source_by_creds_valid
            "Escalation by Creds valid" = $escalation_by_creds_valid
            OS                          = $os
            "Forti model"               = $forti_model
            "Forti version"             = $forti_version
            "Credentialed checks : yes" = $is_credentialed
            "Scan info: Username"       = $user_by_nessus_scan_info
            "Scan Name"                 = $scan_name_by_nessus_scan_info
            "Scanner IP"                = $scanner_ip_by_nessus_scan_info
        }
    
        if (!$EnableFortiDeviceDetection) {
            $row.psobject.properties.remove('Forti model')
            $row.psobject.properties.remove('Forti version')
        }
        if ($ExcludeScanName) {
            $row.psobject.properties.remove('Scan Name')
        }
        if ($ExcludeScannerIP) {
            $row.psobject.properties.remove('Scanner IP')
        }
    
        if ($CheckPluginsPresence) {
            $CheckPluginsPresence | ForEach-Object {
                $plugin_id = $_
                $plugin_name = $plugin_id
                if ($PluginNamesHashTable -and ($plugin_id -in $PluginNamesHashTable.Keys) -and ($PluginNamesHashTable[$plugin_id])) {
                    $plugin_name = $PluginNamesHashTable[$plugin_id]
                }
                $is_plugin_found_for_ip = $ip -in ($scan_csv | Where-Object -Property $plugin_id_column_name -Like $plugin_id).$ip_address_column_name
                $row | Add-Member -MemberType NoteProperty -Name $plugin_name -Value $is_plugin_found_for_ip
            }
        }
    
        $report_ips += $row
    
        $current_index += 1
    }
    
    Write-Output "IPs processed"
    
    $report_file_name = "$($input_csv_file.Basename)-analytics.csv"
    
    if ($OutputCsvName) { $report_file_name = $OutputCsvName }
    
    Write-Output "Creating result file '$($report_file_name)'"
    
    $report_ips | Export-Csv -Path $report_file_name -NoTypeInformation
    
    Write-Output "Result file '$($report_file_name)' created"
    
    if ($SaveExportWithNoInfoPlugins) {
        $export_file_name = "$($input_csv_file.Basename)-no-info-plugins.csv"
        Write-Output "Creating export file '$($export_file_name)'"
        $export_plugins = $scan_csv | Where-Object -Property $severity_column_name -NotMatch $info_severity_value
        if (!$export_plugins) {
            Write-Output "Warning: No plugins found after removing Info. Nothing to export to file $($export_file_name)"
        }
        $export_plugins | Export-Csv -Path $export_file_name -NoTypeInformation
        Write-Output "Plugins exported to '$($export_file_name)'"
    }
    
    Write-Output "Done"
    
}