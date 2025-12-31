@{
    # Script module or binary module file associated with this manifest.
    RootModule        = 'AutoSecure-VPN.psm1'

    # Version number of this module.
    ModuleVersion     = '1.0.6'

    # Supported PSEditions
    # CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID              = 'a1b2c3d4-e5f6-7890-1234-567890abcdef'

    # Author of this module
    Author            = 'Jente'

    # Company or vendor of this module
    CompanyName       = 'AutoSecure'

    # Copyright statement for this module
    Copyright         = '(c) 2025 AutoSecure. All rights reserved.'

    # Description of the functionality provided by this module
    Description       = 'Automated OpenVPN Setup and Configuration for Windows Servers and Clients. Supports bulk client creation via CSV.'

    # Minimum version of the Windows PowerShell engine required by this module
    # PowerShellVersion = ''

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module
    # CLRVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module, for best performance, do not use wildcards
    # Export all functions so they're available in remote sessions
    FunctionsToExport = @('*')

    # Cmdlets to export from this module
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = @('*')

    # Aliases to export from this module
    AliasesToExport   = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    FileList = @(
        'AutoSecure-VPN.psd1',
        'AutoSecure-VPN.psm1',
        'Stable.psd1.example',
        'Variable.psd1.example'
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags       = @('VPN', 'OpenVPN', 'Security', 'Automation', 'Windows')

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/jente01t/AutoSecure-VPN/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/jente01t/AutoSecure-VPN'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            # ReleaseNotes = ''
        }
    }

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from the module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
}




