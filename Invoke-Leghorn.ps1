
########################################################
#
# Leghorn code for PKI abuse
# Author: @remiescourrou
#
########################################################


######################
## PKI Flags Helper ##
######################


function Convert-msPKICertificateNameFlag {
	
<#
.SYNOPSIS

The msPKI-Certificate-Name-Flag attribute specifies the subject name flags
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1

.PARAMETER FSR

Specifies the integer flag

#>

	[CmdletBinding()]
	Param(
		[Int]
		$FSR
	)

	# 

	$msPKI_Certificate_Name_Flag = @{
		[uint32]'0x00000001' = 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT'
		[uint32]'0x00010000' = 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME'
		[uint32]'0x00400000' = 'CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS'
		[uint32]'0x01000000' = 'CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID'
		[uint32]'0x02000000' = 'CT_FLAG_SUBJECT_ALT_REQUIRE_UPN'
		[uint32]'0x04000000' = 'CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL'
		[uint32]'0x08000000' = 'CT_FLAG_SUBJECT_ALT_REQUIRE_DNS'
		[uint32]'0x10000000' = 'CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN'
		[uint32]'0x20000000' = 'CT_FLAG_SUBJECT_REQUIRE_EMAIL'
		[uint32]'0x40000000' = 'CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME'
		[uint32]'0x80000000' = 'CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH'
		[uint32]'0x00000008' = 'CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME'
	}

	$Certificate_Name_Flags = @()

	$Certificate_Name_Flags += $msPKI_Certificate_Name_Flag.Keys | Where-Object { $FSR -band $_ } | ForEach-Object { $msPKI_Certificate_Name_Flag[$_] }

	($Certificate_Name_Flags | Where-Object {$_}) -join ','
}


function Convert-msPKIEnrollmentFlag {
	
<#
.SYNOPSIS

The msPKI-Enrollment-Flag attribute specifies the enrollment flags
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1

.PARAMETER FSR

Specifies the integer flag

#>
	
	[CmdletBinding()]
	Param(
		[Int]
		$FSR
	)

	$msPKI_Enrollment_Flag = @{
		[uint32]'0x00000001' = 'CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS'
		[uint32]'0x00000002' = 'CT_FLAG_PEND_ALL_REQUESTS'
		[uint32]'0x00000004' = 'CT_FLAG_PUBLISH_TO_KRA_CONTAINER'
		[uint32]'0x00000008' = 'CT_FLAG_PUBLISH_TO_DS'
		[uint32]'0x00000010' = 'CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE'
		[uint32]'0x00000020' = 'CT_FLAG_AUTO_ENROLLMENT'
		[uint32]'0x00000040' = 'CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT'
		[uint32]'0x00000100' = 'CT_FLAG_USER_INTERACTION_REQUIRED'
		[uint32]'0x00000400' = 'CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE'
		[uint32]'0x00000800' = 'CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF'
		[uint32]'0x00001000' = 'CT_FLAG_ADD_OCSP_NOCHECK'
		[uint32]'0x00002000' = 'CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL'
		[uint32]'0x00004000' = 'CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS'
		[uint32]'0x00008000' = 'CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS'
		[uint32]'0x00010000' = 'CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT'
		[uint32]'0x00020000' = 'CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST'
	}

	$Enrollment_Flags = @()

	$Enrollment_Flags += $msPKI_Enrollment_Flag.Keys | Where-Object { $FSR -band $_ } | ForEach-Object { $msPKI_Enrollment_Flag[$_] }

	($Enrollment_Flags | Where-Object {$_}) -join ','
}


function Convert-flags {
	
	
<#
.SYNOPSIS

The flags attribute is the general-enrollment flags attribute
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/6cc7eb79-3e84-477a-b398-b0ff2b68a6c0

.PARAMETER FSR

Specifies the integer flag

#>
	
	[CmdletBinding()]
	Param(
		[Int]
		$FSR
	)
	#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/6cc7eb79-3e84-477a-b398-b0ff2b68a6c0

	$msPKI_flags = @{
		[uint32]'0x00000020' = 'CT_FLAG_AUTO_ENROLLMENT'
		[uint32]'0x00000040' = 'CT_FLAG_MACHINE_TYPE'
		[uint32]'0x00000080' = 'CT_FLAG_IS_CA'
		[uint32]'0x00000200' = 'CT_FLAG_ADD_TEMPLATE_NAME'
		[uint32]'0x00000800' = 'CT_FLAG_IS_CROSS_CA'
		[uint32]'0x00010000' = 'CT_FLAG_IS_DEFAULT'
		[uint32]'0x00020000' = 'CT_FLAG_IS_MODIFIED'
		[uint32]'0x00000400' = 'CT_FLAG_DONOTPERSISTINDB'
		[uint32]'0x00000002' = 'CT_FLAG_ADD_EMAIL'
		[uint32]'0x00000008' = 'CT_FLAG_PUBLISH_TO_DS'
		[uint32]'0x00000010' = 'CT_FLAG_EXPORTABLE_KEY'
	}

	$Flags = @()



	# get flag info
	$Flags = $msPKI_flags.Keys | Where-Object { $FSR -band $_ } | ForEach-Object { $msPKI_flags[$_] }
	
	($Flags | Where-Object {$_}) -join ','
}


######################
## AD object Helper ##
######################


function Query-Objects_light {
<#
.SYNOPSIS
  
Runs a custom LDAP Query.

.PARAMETER Domain
  
Specifies the domain name to query for, defaults to the current domain.
  
.PARAMETER LdapPort
  
Specifies the LDAP port on which to query, defaults to 389
  
.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials 
for connection to the target domain.

.PARAMETER Filter

The ldap search filter.
If not specified, returns all objects

.PARAMETER Attributes

The list of attributes. 
If not specified, returns all attributes.

.PARAMETER Max

Maximum number of results to return. 
If not specifies, returns all results.

.PARAMETER SecurityMasks

SecurityMask to extract ACL or Owner

#>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
      
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LdapPort = "389",
         
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        
        [ValidateSet('Dacl','Sacl','Owner','All')]
        [String]
        $SecurityMasks,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Filter,
        
        [Parameter(Mandatory=$False)]
        [String]
        $SearchBase,
        
        [Parameter(Mandatory=$False)]
        [String[]]
        $Attributes,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [int]
        $Max = 1000
    )
    
    process {

        If (-Not $PSBoundParameters['Filter']) {
          $Filter = "(&(objectCategory=*))"
        }

        if($SearchBase){
            $SearchBase = "LDAP://$SearchBase"
        }
        else {
            $SearchBase = "LDAP://${Domain}:${LdapPort}"
        }
        

        if ($Credential.UserName -ne $null){
            $NetworkCredential = $Credential.GetNetworkCredential()
            $UserName = $NetworkCredential.UserName
            $Password = $NetworkCredential.Password
            $ObjDomain = New-Object System.DirectoryServices.DirectoryEntry $SearchBase, $UserName, $Password
        } else {
            $ObjDomain = New-Object System.DirectoryServices.DirectoryEntry $SearchBase
        }

        $Searcher = New-Object System.DirectoryServices.DirectorySearcher 
        $Searcher.SearchRoot = $ObjDomain
        $Searcher.PageSize = $Max 
        
        if ($PSBoundParameters['SecurityMasks']) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
				'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
            }
        }
        
        If ($Attributes) {
            $Searcher.PropertiesToLoad.Clear() | Out-Null
            $Searcher.PropertiesToLoad.AddRange($Attributes)
        }
        
        $Searcher.SearchScope = "Subtree"
        $Searcher.Filter = $Filter
      
        Try {
			$Results = $Searcher.FindAll()
			return $Results
        }
        Catch {
            $Log = "[-] No result found for LDAP query."
            Write-Verbose "[-] No result found for LDAP query : $_"
        }
    }
}


function Get-CertificateTemplate {

<#
.SYNOPSIS
  
Extract all CertificateTemplate inside Public Key Services

.PARAMETER Domain
  
Specifies the domain name to query for, defaults to the current domain.
  
.PARAMETER LdapPort
  
Specifies the LDAP port on which to query, defaults to 389
  
.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials 
for connection to the target domain.

#>

    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LdapPort = "389",
		
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $RemoveAdminACL,
         
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
	
	process {
                
		$DomainTab = $Domain.Replace(".",",DC=")
		
		$Attributes = "cn","name","msPKI-Certificate-Name-Flag","Flags","msPKI-Certificate-Application-Policy","ntsecuritydescriptor","displayName","msPKI-Enrollment-Flag"
		$SearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$DomainTab"
		
		$Results = Query-Objects_light -Domain $Domain -LdapPort $LdapPort -Credential $Credential -Filter "(flags=*)" -Attributes $Attributes -SearchBase $SearchBase -SecurityMasks "Owner"
		
		$CertificateTemplates = @()
		
		foreach ($Result in $Results){
			
			$CertificateTemplate = New-Object -TypeName psobject
			
			$CertificateTemplate | Add-Member -MemberType NoteProperty -Name cn -Value $Result.Properties["cn"][0]
			$CertificateTemplate | Add-Member -MemberType NoteProperty -Name name -Value $Result.Properties["name"][0]
			$CertificateTemplate | Add-Member -MemberType NoteProperty -Name displayName -Value $Result.Properties["displayName"][0]

			ForEach ($Attribute in $Attributes){
				if ($Attribute -eq 'msPKI-Certificate-Name-Flag') {
					# convert the flags to a string
					# $Result.Properties[$Attribute] = Convert-msPKICertificateNameFlag ($Result.Properties[$Attribute])[0]
					$msPKICertificateNameFlag = Convert-msPKICertificateNameFlag ($Result.Properties[$Attribute])[0]				
					$CertificateTemplate | Add-Member -MemberType NoteProperty -Name "msPKI_Certificate_Name_Flag" -Value $msPKICertificateNameFlag
				}
				elseif ($Attribute -eq 'Flags'){
					# convert the flags to a string
					# $Result.Properties[$Attribute] = Convert-Flags ($Result.Properties[$Attribute])[0]
					$Flags = Convert-Flags ($Result.Properties[$Attribute])[0]
					$CertificateTemplate | Add-Member -MemberType NoteProperty -Name "Flags" -Value $Flags
				}
				elseif ($Attribute -eq 'msPKI-Enrollment-Flag'){
					$msPKIEnrollmentFlag = Convert-msPKIEnrollmentFlag ($Result.Properties[$Attribute])[0]
					$CertificateTemplate | Add-Member -MemberType NoteProperty -Name "msPKI_Enrollment_Flag" -Value $msPKIEnrollmentFlag
				}
			}
			
			$CertificateApplicationPolicy = ""

			$CertificateApplicationPolicy = $Result.Properties["msPKI-Certificate-Application-Policy"]
			$CertificateTemplate | Add-Member -MemberType NoteProperty -Name "msPKI_Certificate_Application_Policy" -Value $CertificateApplicationPolicy
			
			$ACLOwner = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Result.Properties.ntsecuritydescriptor[0],0		
			$CertificateTemplate | Add-Member -MemberType NoteProperty -Name OwnerSID -Value $ACLOwner.Owner.Value
			
			try {
				if($RemoveAdminACL) {
					if (($objSID -like "*-512") -or ($objSID -like "*-519") -or ($objSID -like "*-516") -or ($objSID -like "*-500") -or ($objSID -like "*-498") -or ($objSID -like "S-1-5-9")) {
						$objUser = ""
					}
				}
				else {
					$objSID = New-Object System.Security.Principal.SecurityIdentifier ($ACLOwner.Owner.Value)
					$objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
				}
			}
			catch { $objUser = ""}
			

			$DomainObjectClean = $Result.Properties["name"][0]
			$ResultsAcl = Query-Objects_light -Domain $Domain -LdapPort $LdapPort -Credential $Credential -Filter "(name=$DomainObjectClean)" -SecurityMasks "Dacl" -SearchBase $SearchBase
			$ACL = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $ResultsAcl.Properties.ntsecuritydescriptor[0], 0
			
			$GenericAll = ""
			$TakeOwnership = ""
			$WriteDacl = ""
			$WriteOwner = ""
			$WriteProperty = ""
			$CertificateEnrollment = ""
			$CertificateAutoEnrollment = ""
				
			$ACl.DiscretionaryAcl | Where-Object { $_.AceQualifier -like "AccessAllowed" } | Foreach-Object {
				
				$objUser =""

				$AccessMaskList =  ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
				
				$objSID = New-Object System.Security.Principal.SecurityIdentifier ($_.SecurityIdentifier)
								
				if($RemoveAdminACL) {
					if (($objSID -like "*-512") -or ($objSID -like "*-519") -or ($objSID -like "*-516") -or ($objSID -like "*-500") -or ($objSID -like "*-498") -or ($objSID -like "S-1-5-9")) {
						return
					}
					try {
						$objUser = [string]$objSID.Translate( [System.Security.Principal.NTAccount])
					}
					catch {return}
				}
				else {
					try {
						$objUser = [string]$objSID.Translate( [System.Security.Principal.NTAccount])
					}
					catch { $objUser = $objSID.Value}
				}

												
				if (([string]$AccessMaskList).Contains("GenericAll")){$GenericAll += $objUser + ", "}
				if (([string]$AccessMaskList).Contains("TakeOwnership")){$TakeOwnership += $objUser + ", "}
				if (([string]$AccessMaskList).Contains("WriteDacl")){$WriteDacl += $objUser + ", "}
				if (([string]$AccessMaskList).Contains("WriteOwner")){$WriteOwner += $objUser + ", "}
				if (([string]$AccessMaskList).Contains("WriteProperty")){
					if ($_.ObjectAceType -in ($null, [guid]::Empty)) {
						$WriteProperty += $objUser + ", "
					}
				}
				if (([string]$AccessMaskList).Contains("ExtendedRight")){if ($_.ObjectAceType -like "0e10c968-78fb-11d2-90d4-00c04f79dc55"){ $CertificateEnrollment += $objUser + ", "}}
				if (([string]$AccessMaskList).Contains("ExtendedRight")){if ($_.ObjectAceType -like "a05b8cc2-17bc-4802-a710-e7c15ab866a2"){ $CertificateAutoEnrollment += $objUser + ", "}}
			}
			
			if ($GenericAll) { $GenericAll = $GenericAll.Substring(0, $GenericAll.Length-2)}
			if ($TakeOwnership) { $TakeOwnership = $TakeOwnership.Substring(0, $TakeOwnership.Length-2)}
			if ($WriteDacl) { $WriteDacl = $WriteDacl.Substring(0, $WriteDacl.Length-2)}
			if ($WriteOwner) { $WriteOwner = $WriteOwner.Substring(0, $WriteOwner.Length-2)}
			if ($WriteProperty) { $WriteProperty = $WriteProperty.Substring(0, $WriteProperty.Length-2)}
			if ($CertificateEnrollment) { $CertificateEnrollment = $CertificateEnrollment.Substring(0, $CertificateEnrollment.Length-2)}
			if ($CertificateAutoEnrollment) { $CertificateAutoEnrollment = $CertificateAutoEnrollment.Substring(0, $CertificateAutoEnrollment.Length-2)}
			
			$CertificateTemplate | Add-Member -MemberType NoteProperty -Name Acl_GenericAll -Value $GenericAll
			$CertificateTemplate | Add-Member -MemberType NoteProperty -Name Acl_TakeOwnership -Value $TakeOwnership
			$CertificateTemplate | Add-Member -MemberType NoteProperty -Name Acl_WriteDacl -Value $WriteDacl
			$CertificateTemplate | Add-Member -MemberType NoteProperty -Name Acl_WriteOwner -Value $WriteOwner
			$CertificateTemplate | Add-Member -MemberType NoteProperty -Name Acl_WriteProperty -Value $WriteProperty
			$CertificateTemplate | Add-Member -MemberType NoteProperty -Name Acl_CertificateEnrollment -Value $CertificateEnrollment
			$CertificateTemplate | Add-Member -MemberType NoteProperty -Name Acl_CertificateAutoEnrollment -Value $CertificateAutoEnrollment
						
			$CertificateTemplates += $CertificateTemplate
		
		}
		
		$CertificateTemplates
		
	}
}


function Get-EnrollmentService {

<#
.SYNOPSIS
  
Extract all Enrollment Service inside Public Key Services

.PARAMETER Domain
  
Specifies the domain name to query for, defaults to the current domain.
  
.PARAMETER LdapPort
  
Specifies the LDAP port on which to query, defaults to 389
  
.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials 
for connection to the target domain.

#>

    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LdapPort = "389",
		
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $RemoveAdminACL,
         
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
	
	process {
                
		$DomainTab = $Domain.Replace(".",",DC=")
		
		$Attributes = "cn","name","dNSHostName","ntsecuritydescriptor","displayName","certificateTemplates"
		$SearchBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=$DomainTab"
		
		$Results = Query-Objects_light -Domain $Domain -LdapPort $LdapPort -Credential $Credential -Filter "(certificateTemplates=*)" -Attributes $Attributes -SearchBase $SearchBase -SecurityMasks "Owner"
		
		$EnrollmentServices = @()
		
		foreach ($Result in $Results){
			
			$EnrollmentService = New-Object -TypeName psobject
			
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name cn -Value $Result.Properties["cn"][0]
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name name -Value $Result.Properties["name"][0]
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name displayName -Value $Result.Properties["displayName"][0]
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name dNSHostName -Value $Result.Properties["dNSHostName"][0]
			
			$hostname = $EnrollmentService.dNSHostName.Split('.')[0]

			$certificateTemplates = ""
			$Result.Properties["certificateTemplates"] | ForEach-Object { $certificateTemplates += [string]$_ + "," }
			if ($certificateTemplates) { $certificateTemplates = $certificateTemplates.Substring(0, $certificateTemplates.Length-1)}
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name "certificateTemplates" -Value $certificateTemplates
			
			$ACLOwner = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Result.Properties.ntsecuritydescriptor[0],0		
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name OwnerSID -Value $ACLOwner.Owner.Value
			
			$objSID = New-Object System.Security.Principal.SecurityIdentifier ($ACLOwner.Owner.Value)
			
			if($RemoveAdminACL) {
				if (($objSID -like "*-512") -or ($objSID -like "*-519") -or ($objSID -like "*-516") -or ($objSID -like "*-500") -or ($objSID -like "*-498") -or ($objSID -like "S-1-5-9")) {
					$objUser = ""
				}
				else{
					try {
						$objSID = New-Object System.Security.Principal.SecurityIdentifier ($ACLOwner.Owner.Value)
						$objUser = $objSID.Translate([System.Security.Principal.NTAccount])
						if($objUser -match $hostname){
							$objUser = ""
						}
					}
					catch {$objUser = ""}
				}
			}
			else {
				try {
					$objSID = New-Object System.Security.Principal.SecurityIdentifier ($ACLOwner.Owner.Value)
					$objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
				}
				catch { $objUser = $objSID.Value}
			}
			
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name Owner -Value $objUser

			$DomainObjectClean = $Result.Properties["name"][0]
			$ResultsAcl = Query-Objects_light -Domain $Domain -LdapPort $LdapPort -Credential $Credential -Filter "(name=$DomainObjectClean)" -SecurityMasks "Dacl" -SearchBase $SearchBase
			$ACL = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $ResultsAcl.Properties.ntsecuritydescriptor[0], 0
			
			$GenericAll = ""
			$TakeOwnership = ""
			$WriteDacl = ""
			$WriteOwner = ""
			$WriteProperty = ""
			$EnrollmentServiceEnrollment = ""
			$EnrollmentServiceAutoEnrollment = ""
			
			$ACl.DiscretionaryAcl | Where-Object { $_.AceQualifier -like "AccessAllowed" } | Foreach-Object {
				
				$objUser =""
				
				$AccessMaskList =  ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
				$objSID = New-Object System.Security.Principal.SecurityIdentifier ($_.SecurityIdentifier)
				
				if($RemoveAdminACL) {
					if (($objSID -like "*-512") -or ($objSID -like "*-519") -or ($objSID -like "*-516") -or ($objSID -like "*-500") -or ($objSID -like "*-498") -or ($objSID -like "S-1-5-9")) {
						return
					}
					try {
						$objUser = [string]$objSID.Translate( [System.Security.Principal.NTAccount])
						if($objUser  -match $hostname){
							return
						}
					}
					catch { 
						return
					}
				}
				else {
					try {
						$objUser = [string]$objSID.Translate( [System.Security.Principal.NTAccount])
					}
					catch { $objUser = $objSID.Value}
				}

				if (([string]$AccessMaskList).Contains("GenericAll")){$GenericAll += $objUser + ", "}
				if (([string]$AccessMaskList).Contains("TakeOwnership")){$TakeOwnership += $objUser + ", "}
				if (([string]$AccessMaskList).Contains("WriteDacl")){$WriteDacl += $objUser + ", "}
				if (([string]$AccessMaskList).Contains("WriteOwner")){$WriteOwner += $objUser + ", "}
				if (([string]$AccessMaskList).Contains("WriteProperty")){
					if ($_.ObjectAceType -in ($null, [guid]::Empty)) {
						$WriteProperty += $objUser + ", "
					}
				}
				if (([string]$AccessMaskList).Contains("ExtendedRight")){if ($_.ObjectAceType -like "0e10c968-78fb-11d2-90d4-00c04f79dc55"){ $EnrollmentServiceEnrollment += $objUser + ", "}}
				if (([string]$AccessMaskList).Contains("ExtendedRight")){if ($_.ObjectAceType -like "a05b8cc2-17bc-4802-a710-e7c15ab866a2"){ $EnrollmentServiceAutoEnrollment += $objUser + ", "}}

			}
			
			if ($GenericAll) { $GenericAll = $GenericAll.Substring(0, $GenericAll.Length-2)}
			if ($TakeOwnership) { $TakeOwnership = $TakeOwnership.Substring(0, $TakeOwnership.Length-2)}
			if ($WriteDacl) { $WriteDacl = $WriteDacl.Substring(0, $WriteDacl.Length-2)}
			if ($WriteOwner) { $WriteOwner = $WriteOwner.Substring(0, $WriteOwner.Length-2)}
			if ($WriteProperty) { $WriteProperty = $WriteProperty.Substring(0, $WriteProperty.Length-2)}
			if ($EnrollmentServiceEnrollment) { $EnrollmentServiceEnrollment = $EnrollmentServiceEnrollment.Substring(0, $EnrollmentServiceEnrollment.Length-2)}
			if ($EnrollmentServiceAutoEnrollment) { $EnrollmentServiceAutoEnrollment = $EnrollmentServiceAutoEnrollment.Substring(0, $EnrollmentServiceAutoEnrollment.Length-2)}
			
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name Acl_GenericAll -Value $GenericAll
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name Acl_TakeOwnership -Value $TakeOwnership
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name Acl_WriteDacl -Value $WriteDacl
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name Acl_WriteOwner -Value $WriteOwner
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name Acl_WriteProperty -Value $WriteProperty
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name Acl_CertificateEnrollment -Value $EnrollmentServiceEnrollment
			$EnrollmentService | Add-Member -MemberType NoteProperty -Name Acl_CertificateAutoEnrollment -Value $EnrollmentServiceAutoEnrollment
				
			$EnrollmentServices += $EnrollmentService
		
		}
		
		$EnrollmentServices
		
	}
}


######################
## PKI Recon        ##
######################


function Invoke-Leghorn {
	
<#
.SYNOPSIS
  
Try to find exploitable scenario in Public Key Infrastructures

.PARAMETER Domain
  
Specifies the domain name to query for, defaults to the current domain.
  
.PARAMETER LdapPort
  
Specifies the LDAP port on which to query, defaults to 389
  
.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials 
for connection to the target domain.

#>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
         
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LdapPort = "389",
         
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
	
    )
	
	process {
		
		
$text = @"

                       //
     ww_          ___.///
    o__ `._.-'''''    //
    |/  \   ,     /   //
         \  ``,,,' _//	
          `-.  \--'     .''.
             \_/_/     '..'
              \\\\	
             ,,','` AsH	


		Invoke-Leghorn
		PKI Analysis 
		@RemiEscourrou
"@

		Write-Host $text
		Write-Host "`n"
		
		Write-Host "[info] Request certificate templates on" $Domain 
		$CertificateTemplates = @()
		
		$CertificateTemplates +=  Get-CertificateTemplate -Domain $Domain -LdapPort $LdapPort -Credential $Credential -RemoveAdminACL
		
		$VulnerableCertificateTemplates = @()
		$ModifiableCertificateTemplates = @()
		
		if($CertificateTemplates){
			
			Write-Host "[info] Found" $CertificateTemplates.Count "certificate templates" 
			
			Write-Host "[info] Search for a vulnerable template"
			
			foreach ($CertificateTemplate in $CertificateTemplates) {
				
				Write-Verbose "[info] Analyzing $($CertificateTemplate.name) configuration"
				
				# Check CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT or CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME
				if ($CertificateTemplate.msPKI_Certificate_Name_Flag -contains "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT" -or $CertificateTemplate.msPKI_Certificate_Name_Flag -contains "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME") {
					Write-Verbose "[CT +??] $($CertificateTemplate.name) is CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT or CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"
				}
				else {
					Write-Verbose "[CT ---] $($CertificateTemplate.name) msPKI-Enrollment-Flag is not CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT or CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"
					continue
				}
				
				# Check not CT_FLAG_PEND_ALL_REQUESTS
				if ($CertificateTemplate.msPKI_Enrollment_Flag -notcontains "CT_FLAG_PEND_ALL_REQUESTS"){
					Write-Verbose "[CT ++?] $($CertificateTemplate.name) is CT_FLAG_PEND_ALL_REQUESTS"
				}
				else {
					Write-Verbose "[CT ---] $($CertificateTemplate.name) msPKI-Enrollment-Flag is not CT_FLAG_PEND_ALL_REQUESTS"
					continue
				}
				
				# Check application policy OID  “Client Authentication” (1.3.6.1.5.5.7.3.2), “Microsoft Smartcard Logon” (1.3.6.1.4.1.311.20.2.2) or “Key Purpose Client Auth” (1.3.6.1.5.2.3.4) or "Any purpose" (2.5.29.15)
				if (($CertificateTemplate.msPKI_Certificate_Application_Policy -contains "1.3.6.1.5.5.7.3.2") -or ($CertificateTemplate.msPKI_Certificate_Application_Policy -contains "1.3.6.1.4.1.311.20.2.2") -or ($CertificateTemplate.msPKI_Certificate_Application_Policy -contains "1.3.6.1.5.2.3.4") -or ($CertificateTemplate.msPKI_Certificate_Application_Policy -contains "2.5.29.15")) {
					Write-Verbose "[CT +++] $($CertificateTemplate.name) contains an interesting application policy OID"
				}
				else {
					Write-Verbose "[CT ++-] $($CertificateTemplate.name) application policy OID is not Client Authentication / Microsoft Smartcard Logon / Key Purpose Client Auth"
					continue
				}
				
				Write-Host "[CT Misconfig]" $CertificateTemplate.name "is a good candidate, including all 3 prerequitises" -ForegroundColor Green
				
				if ($CertificateTemplate.Acl_CertificateEnrollment) {
					Write-Host "[CT Misconfig]" $CertificateTemplate.name "can be requested (Enrollment) by" $CertificateTemplate.Acl_CertificateEnrollment
				}
				else {
					Write-Host "[CT Misconfig]" $CertificateTemplate.name "cannot be requested"
				}
				
				$VulnerableCertificateTemplates += $CertificateTemplate
			}
			
			Write-Host "[info] Search for a modifiable template (Admin ACEs are removed)"
			Write-Host "[info] Admin ACEs removed are *-512 *-519 *-516 *-500 *-498 S-1-5-9 and unresolve SID"
		
			foreach ($CertificateTemplate in $CertificateTemplates) {

				Write-Verbose "[info] Analyzing $($CertificateTemplate.name) ACEs"
				$Modifiable = $FALSE

				if($CertificateTemplate.Acl_GenericAll) {
					Write-Verbose "[CT Modifiable] $($CertificateTemplate.name) could be modified (GenericAll) by $($CertificateTemplate.Acl_GenericAll)"
					$Modifiable = $TRUE
				}
				if($CertificateTemplate.Acl_TakeOwnership) {
					Write-Verbose "[CT Modifiable] $($CertificateTemplate.name) could be modified (TakeOwnership) by $($CertificateTemplate.Acl_TakeOwnership)"
					$Modifiable = $TRUE
				}
				if($CertificateTemplate.Acl_WriteDacl) {
					Write-Verbose "[CT Modifiable] $($CertificateTemplate.name) could be modified (WriteDacl) by $($CertificateTemplate.Acl_WriteDacl)"
					$Modifiable = $TRUE
				}
				if($CertificateTemplate.Acl_WriteOwner) {
					Write-Verbose "[CT Modifiable] $($CertificateTemplate.name) could be modified (WriteOwner) by $($CertificateTemplate.Acl_WriteOwner)"
					$Modifiable = $TRUE
				}
				if($CertificateTemplate.Acl_WriteProperty) {
					Write-Verbose "[CT Modifiable] $($CertificateTemplate.name) could be modified (WriteProperty) by $($CertificateTemplate.Acl_WriteProperty)"
					$Modifiable = $TRUE
				}
				
				if ($Modifiable) {
					Write-Host "[CT Modifiable] $($CertificateTemplate.name) can be modified (ACEs) by non Admin User (Generic SID)" -ForegroundColor Green
					$ModifiableCertificateTemplates += $CertificateTemplate
				}
			}
		}
		else{
			Write-Host "[CT -] No certificate templates" -ForegroundColor DarkMagenta
		}
		
		$EnrollmentServices = @()
		Write-Host "[info] Request enrollment service on" $Domain
		$EnrollmentServices +=  Get-EnrollmentService -Domain $Domain -LdapPort $LdapPort -Credential $Credential -RemoveAdminACL
		
		if ($EnrollmentServices){
			
			Write-Host "[info] Found" $EnrollmentServices.Count "enrollment services"
						
			foreach ($EnrollmentService in $EnrollmentServices) {
				
				Write-Host "[info] Analyzing $($EnrollmentService.name)"
				Write-Host "[info] Admin ACEs removed are *-512 *-519 *-516 *-500 *-498 S-1-5-9 PKI servers and unresolved SID"
				
				$EnrollmentModifiable = $FALSE
				$PublishModifiable = $FALSE
				
				if($EnrollmentService.Acl_GenericAll) {
					Write-Verbose "[ES Modifiable] $($EnrollmentService.name) could be modified (GenericAll) by $($EnrollmentService.Acl_GenericAll)"
					$EnrollmentModifiable = $TRUE
					$PublishModifiable = $TRUE
				}
				if($EnrollmentService.Acl_TakeOwnership) {
					Write-Verbose "[ES Modifiable] $($EnrollmentService.name) could be modified (TakeOwnership) by $($EnrollmentService.Acl_TakeOwnership)"
					$EnrollmentModifiable = $TRUE
					$PublishModifiable = $TRUE
				}
				if($EnrollmentService.Acl_WriteDacl) {
					Write-Verbose "[ES Modifiable] $($EnrollmentService.name) could be modified (WriteDacl) by $($EnrollmentService.Acl_WriteDacl)"
					$EnrollmentModifiable = $TRUE
					$PublishModifiable = $TRUE
				}
				if($EnrollmentService.Acl_WriteOwner) {
					Write-Verbose "[ES Modifiable] $($EnrollmentService.name) could be modified (WriteOwner) by $($EnrollmentService.Acl_WriteOwner)"
					$EnrollmentModifiable = $TRUE
					$PublishModifiable = $TRUE
				}
				if($EnrollmentService.Acl_WriteProperty) {
					Write-Verbose "[ES Modifiable] $($EnrollmentService.name) could be modified (WriteProperty) by $($EnrollmentService.Acl_WriteProperty)"
					$PublishModifiable = $TRUE
				}

				if ($EnrollmentService.Acl_CertificateEnrollment -or $EnrollmentModifiable) {
					if($EnrollmentService.Acl_CertificateEnrollment){
						Write-Host "[info]" $EnrollmentService.name "can be requested (Enrollment) by" $EnrollmentService.Acl_CertificateEnrollment
					}
					if($EnrollmentModifiable){
						Write-Host "[info]" $EnrollmentService.name "can be modified (Enrollment ACEs) by non Admin User (Generic SID)" 
						
					}
					
					foreach ($VulnerableCertificateTemplate in $VulnerableCertificateTemplates){
						if ($EnrollmentService.certificateTemplates.contains($VulnerableCertificateTemplate.name)){
							Write-Host "[CT Misconfig | ES OK]" $VulnerableCertificateTemplate.name "is exploitable and is published on" $EnrollmentService.name -ForegroundColor Green
						}
						else {
							if($PublishModifiable){
								Write-Host "[CT Misconfig | ES Modifiable]" $VulnerableCertificateTemplate.name "is exploitable and could be published on" $EnrollmentService.name -ForegroundColor Green
							}								
							else{
								Write-Host "[CT Misconfig | ES NOK]" $VulnerableCertificateTemplate.name "is not pusblished on" $EnrollmentService.name
							}
						}
					}
					
					foreach ($ModifiableCertificateTemplate in $ModifiableCertificateTemplates){
						if ($EnrollmentService.certificateTemplates.contains($ModifiableCertificateTemplate.name)){
							Write-Host "[CT Modifiable | ES OK]" $ModifiableCertificateTemplate.name "is modifiable and is published on" $EnrollmentService.name -ForegroundColor Green
						}
						else {
							if($PublishModifiable){
								Write-Host "[CT Modifiable | ES Modifiable]" $ModifiableCertificateTemplate.name "is modifiable and could be published on" $EnrollmentService.name -ForegroundColor Green
							}								
							else{
								Write-Host "[CT Modifiable | ES NOK]" $ModifiableCertificateTemplate.name "is not pusblished on" $EnrollmentService.name
							}
						}
					}
				}
				else {
					Write-Host "[ES NOK]" $EnrollmentService.name "cannot be requested or modified ... sorry" -DarkMagenta
				}
			}
		}
		else {
			Write-Host "[ES -] No Enrollment Service present"
		}
	}
}
