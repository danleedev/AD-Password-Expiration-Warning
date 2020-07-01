$erroractionpreference = "SilentlyContinue"
###############################################################################
# Project:		Password Expiration Warning
# Version:		1.0
# Asset:		PasswordExpirationWarning.ps1
#
# Description:	Script to warn users of their password expiration within a specified threshold.
#	
# Requires:	Interpreter:	PowerShell 1.0 or greater
#			Service:		Active Directory, SMTP Server
#			Credentials:	Executor account must have LDAP read access to user objects and send rights on SMTP server
#
# Inputs:	Accepts a configuration file in XML format with the following structure (data provided is for example only):
#
#			<?xml version="1.0"?>
#			<config>
#				<smtp>172.16.210.108</smtp>
#				<adminemail>akshay.shetty@miu.edu.my</adminemail>
#				<policy>60</policy>
#				<upperthreshold>15</upperthreshold>
#				<lowerthreshold>7</lowerthreshold>
#				<email>
#					<subject>Network Password Expiration Warning!</subject>
#					<body>
#						<![CDATA[
#						Dear [USERNAME],
#						
#						Your password will expire in [DAYSTOEXPIRATION] days.  Please log in and change it at your earliest convenience.
#						
#						Thank you,
#						Network Systems Administration
#						]]>
#					</body>
#				</email>
#				<exclusions>
#					<exclusion>administrator</exclusion>
#					<exclusion>guest</exclusion>
#				</exclusions>
#			</config>
#
# Outputs:	Sends email to each user whose password will expire within the specified threshold.
#			Outputs a comma delimeted file with one line for each user account indicating the action taken. 
#
# Change Log:
# Version 1.0 - 2012.03.03
#	- Daniel Lee: first executable; implements intial requirements
#
###############################################################################

# Identity
set-variable -name constStrProjectName -option constant -value "PasswordExpirationWarning"
set-variable -name constStrProjectVersion -option constant -value "v1.0"

write-host "`n$constStrProjectName`n$constStrProjectVersion`n"
	
# Asset Validation

	# Configuration File
	if ( ! ( test-path -path ( $constStrProjectName + ".xml" ) ) ) { write-warning "Failed: XML Configuration File Not Found."; exit }
	$xmlConfig = [xml]( gc ( $constStrProjectName + ".xml" ) )

	# SMTP Server
	$strSMTPServer = [string]$xmlConfig.config.smtp
	if ( $strSMTPServer -eq $null ) { write-warning "Failed: XML Configuration File Does Not Properly Specify SMTP Server."; exit }
	$objPing = gwmi -query ( "select * from win32_pingstatus where Address = '" + $strSMPTServer + "'" )
	if ( ( $objPing | ?{ $_.statuscode -eq 0 } ) -eq $null ) { write-warning "Failed: Specified SMTP Server Does Not Respond."; exit }
	if ( ( $objPing | ?{ $_.primaryAddressResolutionStatus -eq 0 } ) -eq $null ) { write-warning "Failed: Specified SMTP Server Name Could Not Be Resolved."; exit }
	$objSMTPClient = new-object Net.Mail.SmtpClient($strSMTPServer)
	if ( $objSMTPClient -eq $null ) { write-warning "Failed: Unable To Create a Mail Client Object For Specified SMTP Server."; exit }
	$strAdminEmail = [string]$xmlConfig.config.adminemail
	
	# Password Expiration
	$intPolicy = [int]$xmlConfig.config.policy
	if ( $intPolicy -eq $null ) { write-warning "Failed: XML Configuration File Does Not Properly Specify Password Aging Policy."; exit }
	if ( (get-date).hour -gt 12 ) { $intThreshold = [int]$xmlConfig.config.upperthreshold } else { $intThreshold = [int]$xmlConfig.config.lowerthreshold }
	if ( $intThreshold -eq $null ) { write-warning "Failed: XML Configuration File Does Not Properly Specify Password Expiration Threshold."; exit }
	
	# Email Message
	$strEmailFrom = [string]$xmlConfig.config.email.from
	if ( $strEmailFrom -eq $null ) { write-warning "Failed: XML Configuration File Does Not Properly Specify Sender For Email."; exit }
	$strEmailSubject = [string]$xmlConfig.config.email.subject
	if ( $strEmailSubject -eq $null ) { write-warning "Failed: XML Configuration File Does Not Properly Specify Subject For Email."; exit }
	$strEmailBody = [string]$xmlConfig.config.email.body."#cdata-section"
	if ( $strEmailBody -eq $null ) { write-warning "Failed: XML Configuration File Does Not Properly Specify Body For Email."; exit }

	# Exclusions
	$aStrExclusions = $xmlConfig.config.exclusions.exclusion
	if ( $aStrExclusions -eq $null ) { write-warning "Failed: XML Configuration File Does Not Properly Specify Accounts For Exclusion."; exit }
	
	# User Objects
	$aObjUsers = gwmi -namespace root/directory/ldap -query "Select ds_sAMAccountName, ds_mail, ds_displayName, ds_pwdLastSet, ds_userAccountControl from ds_user"
	if ( $aObjUsers -eq $null ) { write-warning "Failed: Unable To Retrieve User Objects From the Domain."; exit }
	
# Work Loop
	if ( test-path -path ( $constStrProjectName + ".csv" ) ) { remove-item -path ( $constStrProjectName + ".csv" ) }
	$intUserCount = $aObjUsers.count
	$intUserCurrent = 0

	$strLineOut = "Username,Days To Expiration,Result"
	add-content -path ( $constStrProjectName + ".csv" ) -value $strLineOut
	
	foreach ( $objUser in $aObjUsers ) {
	
		$intUserCurrent++

		$intDaysToPasswordExpiry = $intPolicy - ([int]( (get-date) - [datetime]::fromFileTime($objUser.ds_pwdLastSet) ).days)
		$strLineOut = $objUser.ds_sAMAccountName + "," + $intDaysToPasswordExpiry + ","
	

		if ( $aStrExclusions -contains $objUser.ds_sAMAccountName ) {
			$strLineOut = $strLineOut + "Skipped: Exclusion List"
		} elseif ( $objUser.ds_userAccountControl -ne 512 ) {
			$strLineOut = $strLineOut + "Skipped: Account Disabled or Password Does Not Expire"
		} elseif ( $intDaysToPasswordExpiry -gt $intThreshold ) {
			$strLineOut = $strLineOut + "Skipped: Days To Expiration Not Within Threshold"
		} else {
			if ( $intDaysToPasswordExpiry -gt 0 ) {
				$strPasswordStateMessage = ( "will expire in " + $intDaysToPasswordExpiry + " days" )
			} else {
				$strPasswordStateMessage = "is expired"
			}
			$strEmailBodyCurrent = $strEmailBody.replace("[USERNAME]",$objUser.ds_displayName).replace("[PASSWORDSTATEMESSAGE]",$strPasswordStateMessage).replace("`t","")
#			$objSMTPClient.send($strEmailFrom,$objUser.ds_mail,$strEmailSubject,$strEmailBodyCurrent)
			$objSMTPClient.send($strEmailFrom,"akshay.shetty@miu.edu.my",$strEmailSubject,$strEmailBodyCurrent)
			$strLineOut = $strLineOut + "Notification Sent"
		}
		
		add-content -path ( $constStrProjectName + ".csv" ) -value $strLineOut
		write-host ( "`r" + ( "(" + $intUserCurrent + " of " + $intUserCount + ") " + $objUser.ds_displayName).padright(79) ) -nonewline
		
	}

$aStrResults = gc ( $constStrProjectName + ".csv" ) -delimiter `0
$objSMTPClient.send($strEmailFrom,$strAdminEmail,( $strEmailSubject + " Results"),$aStrResults)
write-host ( "`r" + ( "Done." ).padright(79) + "`n" )
	