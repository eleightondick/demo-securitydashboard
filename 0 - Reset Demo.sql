/*

	Copyright (c) 2020 Ed Leighton-Dick
	
	License: https://edleightondick.com/about/legal-notices/#license

*/

/****************************************************************
  RUN THIS SCRIPT IN SQLCMD MODE
****************************************************************/

-- Check for the existence of a needed directory and create it, if necessary
DECLARE @resetXpcmdshell BIT = 0;

IF (SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell') = 0 BEGIN
	EXECUTE sp_configure 'show advanced options', 1;
	RECONFIGURE;
	EXECUTE sp_configure 'xp_cmdshell', 1;
	RECONFIGURE;
	EXECUTE sp_configure 'show advanced options', 0;
	RECONFIGURE;
	SET @resetXpcmdshell = 1;
END;

EXECUTE xp_cmdshell 'if not exist C:\Temp\SqlAudit mkdir C:\Temp\SqlAudit', no_output;

IF @resetXpcmdshell = 1 BEGIN
	EXECUTE sp_configure 'show advanced options', 1;
	RECONFIGURE;
	EXECUTE sys.sp_configure 'xp_cmdshell', 0;
	RECONFIGURE;	
	EXECUTE sp_configure 'show advanced options', 0;
	RECONFIGURE;
END;

--------------------

USE master;
GO

BEGIN TRY
	IF NOT EXISTS (SELECT 'x' FROM sys.databases WHERE name = 'AdventureWorks2019')
		RAISERROR ('AdventureWorks database does not exist', 16, 1);

	IF NOT EXISTS (SELECT 'x' FROM sys.databases WHERE name = 'SecurityCollector')
		RAISERROR ('SecurityCollector database does not exist', 16, 1);

	IF NOT EXISTS (SELECT 'x' FROM sys.databases WHERE name = 'SecurityDashboard')
		RAISERROR ('SecurityDashboard database does not exist', 16, 1);

	IF EXISTS (SELECT 'x' FROM sys.server_audit_specifications WHERE name = 'SecurityCollector_Connections') BEGIN
		ALTER SERVER AUDIT SPECIFICATION [SecurityCollector_Connections]
			WITH (STATE = OFF);
		DROP SERVER AUDIT SPECIFICATION SecurityCollector_Connections;
	END;
	IF EXISTS (SELECT 'x' FROM sys.server_audits WHERE name = 'SecurityCollector') BEGIN
		ALTER SERVER AUDIT [SecurityCollector]
			WITH (STATE = OFF);
		DROP SERVER AUDIT SecurityCollector;
	END;

	IF NOT EXISTS (SELECT 'x' FROM sys.symmetric_keys WHERE [name] = '##MS_DatabaseMasterKey##')
		CREATE MASTER KEY
			ENCRYPTION BY PASSWORD = 'Y:8pdbC2oEG6iC=?';
	CREATE CERTIFICATE cerTDE
		WITH SUBJECT = 'TDE certificate';
	BACKUP CERTIFICATE cerTDE
		TO FILE = 'C:\Temp\cerTDE.cer'
		WITH PRIVATE KEY (FILE = 'C:\Temp\cerTDE.pvk',
						  ENCRYPTION BY PASSWORD = '2yZU!C#Z@&n7j3M~');
END TRY
BEGIN CATCH
	DECLARE @errorMessage NVARCHAR(4000) = ERROR_MESSAGE();
	DECLARE @errorSeverity INT = ERROR_SEVERITY();
	DECLARE @errorState INT = ERROR_STATE();

	RAISERROR (@errorMessage, @errorSeverity, @errorState);
END CATCH;
