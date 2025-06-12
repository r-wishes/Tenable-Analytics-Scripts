Creates a scan analytics report for a Tenable authenticated scan (not suitable for vulnerabilities search export). Output: a CSV file containing each of the unique IPs in a scan, providing such information as:
* Presence of plugins indicating valid credentials provided or credentials failure
* Authentication information provided by plugin "Target Credential Status by Authentication Protocol - Valid Credentials Provided" - User, Port, Proto, Method, Source, Escalation
* OS information returned by plugin "OS Identification"
* Optionally, FortiOS Model and Version by "Fortinet Device Detection" plugin
* String "Credentialed checks : yes," presented in plugin "Nessus Scan Information" output
* Other information found in "Nessus Scan Information" output: Username (in case of credentialed checks), Scan Name, Scanner IP

Optionally, can accept additional plugin IDs and custom column names for them as hashtable (see examples) to check if this plugin ID is present for each IP (True/False)
Using other parameters, you can exclude some columns, provide a custom output file name, and save the same export with Info plugins filtered out.

Tested on Tenable.SC scan exports. Assumes each unique IP contains only one of each of the following plugins:
* Nessus Scan Information - 19506
* Ping the remote host - 10180
* Target Credential Status by Authentication Protocol - Valid Credentials Provided - 141118
* Target Credential Status by Authentication Protocol - Failure for Provided Credentials - 104410
* OS Identification - 11936
* Fortinet Device Detection - 73522 (optional)

Also assumes presence of the following columns:
* Plugin ID (or Plugin on TVM)
* Plugin Name
* IP Address
* Plugin Output
* Severity

Static values can be customized inside the script to accommodate for other solutions.

Help information:
```
NAME
    Invoke-AnalyticsReport

SYNOPSIS
    Creates an analytics report for Tenable authenticated scan (not suitable for vulnerabilities search export).


SYNTAX
    Invoke-AnalyticsReport [-InputCsvPath] <String> [[-OutputCsvName] <String>] [-ExcludeScanName] [[-CheckPluginsPresence] <Int32[]>]
    [[-PluginNamesHashTable] <Hashtable>] [-SaveExportWithNoInfoPlugins] [-EnableFortiDeviceDetection] [<CommonParameters>]


DESCRIPTION
    Parses Nessus scan CSV exports to identify authentication results per IP, such as whether each IP has plugins: "Valid Credentials Provided"    
    (141118), "Failure for Provided Credentials" (104410), "Nessus Scan Information" (19506). Additionally, uses "OS Identification" (11936) to    
    list the host's OS and attempts to identify the succeeded username, if any. Optional functionalities described in parameters.


PARAMETERS
    -InputCsvPath <String>
        Specifies the scan export file name (.csv).


    -OutputCsvName <String>
        Specifies the analytics report file name (.csv). By default appends "-analytics" to the original file name.


    -ExcludeScanName [<SwitchParameter>]
        Excludes Scan Name column.


    -CheckPluginsPresence <Int32[]>
        Accepts comma-separated integer Plugin IDs. Adds columns for each Plugin ID provided, checking whether the plugins are present for IPs.    
        Example: -CheckPluginsPresence 102094,14272


    -PluginNamesHashTable <Hashtable>
        Used with CheckPluginsPresence. Accepts a PowerShell HashTable object, where keys are Plugin IDs (integer type), and values are the        
        corresponding column names (string type). Expects column names defined for each Plugin ID provided in CheckPluginsPresence. Use carefully. 


    -SaveExportWithNoInfoPlugins [<SwitchParameter>]
        Deletes Info plugins and saves the rest in a separate file, appending "-no-info-plugins" to the original file name.


    -EnableFortiDeviceDetection [<SwitchParameter>]
        Works if Fortinet devices are in scope. Uses plugin "Fortinet Device Detection" (73522) to add columns "Forti model" and "Forti version"   
        to the report.


INPUTS
    None. You can't pipe objects to Invoke-AnalyticsReport.


OUTPUTS
    Analytics report file (.csv). Optionally: plugins export file with no info plugins (.cvs).


    -------------------------- EXAMPLE 1 --------------------------

    PS>Invoke-AnalyticsReport -InputCsvPath vulns.csv


    -------------------------- EXAMPLE 2 --------------------------

    PS>Invoke-AnalyticsReport -InputCsvPath vulns.csv -OutputCsvName report.csv


    -------------------------- EXAMPLE 3 --------------------------

    PS>Invoke-AnalyticsReport -InputCsvPath vulns.csv -OutputCsvName report.csv


    -------------------------- EXAMPLE 4 --------------------------

    PS>Invoke-AnalyticsReport -InputCsvPath vulns.csv -OutputCsvName report.csv -SaveExportWithNoInfoPlugins -EnableFortiDeviceDetection
    -ExcludeScanName


    -------------------------- EXAMPLE 5 --------------------------

    PS>Invoke-AnalyticsReport -InputCsvPath vulns.csv -CheckPluginsPresence 102094 -PluginNamesHashTable @{102094 = "Privs Issue"}
    -SaveExportWithNoInfoPlugins
```
