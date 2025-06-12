<#
.SYNOPSIS
    Determine if an IP address exists in the specified subnet.
.EXAMPLE
    PS C:\>Test-IpAddressInSubnet 192.168.1.10 -Subnet '192.168.1.1/32','192.168.1.0/24'
    Determine if the IP address exists in the specified subnet.
.INPUTS
    System.Net.IPAddress
#>
function Test-IpAddressInSubnet {
    [CmdletBinding()]
    [OutputType([bool], [string[]])]
    param (
        # IP Address to test against provided subnets.
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [ipaddress[]] $IpAddresses,
        # List of subnets.
        [Parameter(Mandatory = $true)]
        [string[]] $Subnets,
        # Return list of matching subnets rather than a boolean result.
        [Parameter(Mandatory = $false)]
        [switch] $ReturnMatchingSubnets
    )

    # From www.powershellgallery.com
    process {
        foreach ($IpAddress in $IpAddresses) {
            [System.Collections.Generic.List[string]] $listSubnets = New-Object System.Collections.Generic.List[string]
            [bool] $Result = $false
            foreach ($Subnet in $Subnets) {
                [string[]] $SubnetComponents = $Subnet.Split('/')

                [int] $bitIpAddress = [BitConverter]::ToInt32($IpAddress.GetAddressBytes(), 0)
                [int] $bitSubnetAddress = [BitConverter]::ToInt32(([ipaddress]$SubnetComponents[0]).GetAddressBytes(), 0)
                [int] $bitSubnetMaskHostOrder = 0
                if ($SubnetComponents[1] -gt 0) {
                    $bitSubnetMaskHostOrder = -1 -shl (32 - [int]$SubnetComponents[1])
                }
                [int] $bitSubnetMask = [ipaddress]::HostToNetworkOrder($bitSubnetMaskHostOrder)

                if (($bitIpAddress -band $bitSubnetMask) -eq ($bitSubnetAddress -band $bitSubnetMask)) {
                    if ($ReturnMatchingSubnets) {
                        $listSubnets.Add($Subnet)
                    }
                    else {
                        $Result = $true
                        continue
                    }
                }
            }

            ## Return list of matches or boolean result
            if ($ReturnMatchingSubnets) {
                if ($listSubnets.Count -gt 1) { Write-Output $listSubnets.ToArray() -NoEnumerate }
                elseif ($listSubnets.Count -eq 1) { Write-Output $listSubnets.ToArray() }
                else {
                    $Exception = New-Object ArgumentException -ArgumentList ('The IP address {0} does not belong to any of the provided subnets.' -f $IpAddress)
                    Write-Error -Exception $Exception -Category ([System.Management.Automation.ErrorCategory]::ObjectNotFound) -CategoryActivity $MyInvocation.MyCommand -ErrorId 'TestIpAddressInSubnetNoMatch' -TargetObject $IpAddress
                }
            }
            else {
                Write-Output $Result
            }
        }
    }
}


function Invoke-IPsInRangesCheck {

    <#
        .SYNOPSIS
        Checks if the supplied IPs belong to provided ranges.

        .DESCRIPTION
        Accepts an array of single IPs and a CSV containing a column with IP ranges to check against (mandatory), presented by individual IPs, ranges like 10.0.0.1-10.255.255.255, and CIDR subnets. Ranges can be combined into one cell, separated by ",", ";", " ", or a combination of these characters. Information about the ranges can be taken from other columns of the Ranges CSV file. Ranges can be taken from TVM scanner groups, tags, SC scan zones, repositories, etc.

        .PARAMETER InputIPs
        Array of IPs to check against the ranges CSV.

        .PARAMETER RangesCsvPath
        Specifies the ranges file name (.csv).

        .PARAMETER IPsRangesColumnName
        Specifies the name of the column containing ranges inside the ranges file.

        .PARAMETER OutputCsvName
        Specifies the output file name (.csv). By default appends "-ranges-match" to the original file name.

        .INPUTS
        None. You can't pipe objects to Invoke-IPsInRangesCheck.

        .OUTPUTS
        File with IPs matching with ranges (.csv).

        .EXAMPLE
        PS> Invoke-IPsInRangesCheck -InputIPs "10.0.0.1","10.0.0.2","10.0.0.254" -RangesCsvPath scanner-groups.csv -IPsRangesColumnName "ipList"

        .EXAMPLE
        PS> Invoke-IPsInRangesCheck -InputIPs (Import-Csv -Path .\test_ips.csv).IP -RangesCsvPath scanner-groups.csv -IPsRangesColumnName "ipList"

#>

    param (
        [Parameter(mandatory = $true)]
        [string[]]$InputIPs,
        [Parameter(mandatory = $true)]
        [string]$RangesCsvPath,
        [Parameter(mandatory = $true)]
        [string]$IPsRangesColumnName,
        [Parameter(mandatory = $false)]
        [string]$OutputCsvName
    )

    # Define statis values
    $single_ip_regex = "^\d+\.\d+\.\d+\.\d+$"
    $ip_range_regex = "^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$"
    $ip_subnet_regex = "^\d+\.\d+\.\d+\.\d+/\d+$"
    $separators = ",; "
    $ips_separated_list = ".*[$($separators)]+.*"

    $ips_to_check = $InputIPs

    if (($ips_to_check.GetType().Name -ne "Object[]" -and $ips_to_check.GetType().Name -ne "String[]") -or $ips_to_check.Count -eq 0) {
        Write-Output $ips_to_check.GetType()
        Write-Output "Invalid array of IPs to check. Exiting..."
        return -1
    }

    $input_csv_path = $RangesCsvPath

    Write-Output "Analyzing file $($input_csv_path)"

    $input_csv_file = Get-Item $input_csv_path
    $ranges_csv = Import-Csv -Path $input_csv_path

    Write-Output "CSV imported"

    if ($ranges_csv.Count -eq 0) {
        Write-Output "CSV file appears empty. Exiting..."
        return -1
    }

    if ($ranges_csv[0].PSObject.Properties.Name -Contains $IPsRangesColumnName) {
        Write-Output "IP Ranges are defined in column $($IPsRangesColumnName)"
    }
    else {
        Write-Output "IP Ranges column is not found in the input CSV file. Exiting..."
        return -1
    }

    $other_columns = $ranges_csv[0].PSObject.Properties.Name | Where { $_ -NotLike $IPsRangesColumnName }

    Write-Output "Splitting ranges"

    $ranges_unpivoted = @()

    foreach ($range in $ranges_csv) { 
        $ips_list = $range.$IPsRangesColumnName
        if ($ips_list -match $ips_separated_list) { 
            $ips_list_split = $ips_list.Split($separators, [System.StringSplitOptions]::RemoveEmptyEntries)
            foreach ($item in $ips_list_split) { 
                if ($item -notmatch $single_ip_regex -and $item -notmatch $ip_range_regex -and $item -notmatch $ip_subnet_regex) {
                    Write-Output "Error: unrecognized IP/range/subnet: $($item). Skipping..."
                    continue
                }
                $row = [PSCustomObject]@{}
                foreach ($column in $other_columns) {
                    $row | Add-Member -MemberType NoteProperty -Name $column -Value $range.$column
                }
                $row | Add-Member -MemberType NoteProperty -Name $IPsRangesColumnName -Value $item
                $ranges_unpivoted += $row
            } 
        }
        elseif ($ips_list -match $single_ip_regex -or $ips_list -match $ip_range_regex -or $ips_list -match $ip_subnet_regex) {
            $ranges_unpivoted += $range
        }
        elseif ($ips_list -eq "") {
            continue
        }
        else {
            Write-Output "Error: unrecognized range IPs: $($ips_list). Skipping..."
            continue
        }
    }

    Write-Output "Splitting the ranges is completed with $($ranges_unpivoted.Count) result items"

    $ips_count = $ips_to_check.Count
    $current_index = 0
    $report_delta = [int]($ips_count / 10)
    $next_report_index = $report_delta

    Write-Output "Starting processing $($ips_count) IPs"


    $ips_ranges_match_result = @()

    foreach ($ip in $ips_to_check) {

        if ($current_index -eq $next_report_index) {
            Write-Output "Processing $($current_index)/$($ips_count) IPs"
            $next_report_index += $report_delta
        }

        if ($ip -notmatch $single_ip_regex) {
            Write-Output "Error: unrecognized IP value: $($ip). Skipping..."
            continue
        }

        foreach ($range_row in $ranges_unpivoted) {

            $range_ips = $range_row.$IPsRangesColumnName.Trim()
            $check_result = $false

            if ($range_ips -match $single_ip_regex) {
                if ($ip.Trim() -eq $range_ips.Trim()) { $check_result = $true }
            }
            elseif ($range_ips -match $ip_range_regex) {
                $start_ip, $end_ip = $range_ips -Split '-'
                # https://stackoverflow.com/questions/62609183/powershell-checking-ip-address-range-based-on-csv-file
                $ip_check = [version]$ip
                $start_value = [version]$start_ip
                $end_value = [version]$end_ip
                $check_result = $ip_check -ge $start_value -and $ip_check -le $end_value
            }
            elseif ($range_ips -match $ip_subnet_regex) {
                $check_result = Test-IpAddressInSubnet $ip -Subnet $range_ips
            }
            else {
                Write-Output "Error: unrecognized range IPs: $($range_ips). Skipping..."
                continue
            }

            if ($check_result) {
                $row = [PSCustomObject]@{IP = $ip }
                foreach ($column in $other_columns) {
                    $row | Add-Member -MemberType NoteProperty -Name $column -Value $range.$column
                }
                $row | Add-Member -MemberType NoteProperty -Name Matching_Range -Value $range_ips
                $ips_ranges_match_result += $row
            }

        }

        $current_index += 1

    }

    Write-Output "IPs processed"
    Write-Output "Total $($ips_ranges_match_result.Count) matches found, with $(($ips_ranges_match_result.IP | Select-Object -Unique).Count) unique IPs"

    $report_file_name = "$($input_csv_file.Basename)-ranges-match.csv"

    if ($OutputCsvName) { $report_file_name = $OutputCsvName }

    Write-Output "Creating result file '$($report_file_name)'"

    $ips_ranges_match_result | Export-Csv -Path $report_file_name -NoTypeInformation

    Write-Output "Result file '$($report_file_name)' created"

}