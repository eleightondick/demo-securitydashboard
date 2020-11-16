/*

	Copyright (c) 2020 Ed Leighton-Dick
	
	License: https://edleightondick.com/about/legal-notices/#license

*/
USE master;

IF EXISTS (SELECT 'x' FROM sys.databases WHERE name = 'SecurityCollector')
	DROP DATABASE [SecurityCollector];

CREATE DATABASE [SecurityCollector];
GO

ALTER AUTHORIZATION ON DATABASE::[SecurityCollector] TO sa;
GO

-- Enable Service Broker
-- Allow cross-database communication
--     NOTE: TRUSTWORTHY is not recommended for production use. Use dialog security instead.
ALTER DATABASE [SecurityCollector]
	SET ENABLE_BROKER, TRUSTWORTHY ON;
GO

USE SecurityCollector;
GO

CREATE MASTER KEY
	ENCRYPTION BY PASSWORD = '_QX@FRu-?3%NzM*E';
GO

-- Enable TDE
CREATE DATABASE ENCRYPTION KEY
	WITH ALGORITHM = AES_256
	ENCRYPTION BY SERVER CERTIFICATE cerTDE;

ALTER DATABASE [SecurityCollector]
	SET ENCRYPTION ON;
GO

CREATE OR ALTER FUNCTION dbo.currentTimezone ()
	RETURNS sysname
AS BEGIN
	DECLARE @timeZone sysname;

	EXECUTE master.dbo.xp_regread 'HKEY_LOCAL_MACHINE', 'SYSTEM\CurrentControlSet\Control\TimeZoneInformation', 'TimeZoneKeyName', @timeZone OUT;
	RETURN @timeZone;
END;
GO

CREATE TABLE dbo.logins_orphaned (
	rowId BIGINT NOT NULL IDENTITY(1,1) PRIMARY KEY,
	[sid] VARBINARY(85) NULL,
	ntLogin sysname NULL,
	firstDiscoveredUtc DATETIME2 NOT NULL DEFAULT(SYSUTCDATETIME()),
	lastRecordedUtc DATETIME2 NOT NULL DEFAULT(SYSUTCDATETIME()));

CREATE TABLE dbo.instance_lastReboot (
	rowId BIGINT NOT NULL IDENTITY(1,1) PRIMARY KEY,
	lastRebootUtc DATETIME2 NOT NULL,
	recordedUtc DATETIME2 NOT NULL DEFAULT(SYSUTCDATETIME()));

CREATE TABLE dbo.instance_certificates (
	rowId BIGINT NOT NULL IDENTITY(1,1) PRIMARY KEY,
	databaseName sysname NULL,
	name sysname NULL,
	keyLength INT NULL,
	expiryDate DATETIME NULL,
	pvtKeyEncryptionType NVARCHAR(60) NULL,
	pvtKeyLastBackup DATETIME2 NULL,
	lastRecordedUtc DATETIME2 NOT NULL DEFAULT(SYSUTCDATETIME()));

CREATE TABLE dbo.audit_bookmark (
	auditName sysname NOT NULL PRIMARY KEY,
	lastFile NVARCHAR(260) NULL,
	lastOffset BIGINT NULL);

INSERT INTO dbo.audit_bookmark (auditName, lastFile, lastOffset)
	VALUES ('SecurityCollector', NULL, NULL);

CREATE TABLE dbo.instance_connections (
	rowId BIGINT NOT NULL IDENTITY(1,1) PRIMARY KEY,
	principalName NVARCHAR(128) NULL,
	principalId INT NULL,
	principalSid VARBINARY(85) NULL,
	clientIp NVARCHAR(128) NULL,
	clientName NVARCHAR(128) NULL,
	clientApplication NVARCHAR(128) NULL,
	connectionTimeUtc DATETIME2 NULL,
	connectionSucceeded BIT NULL,
	connectionFailureState INT NULL,
	recordedUtc datetime2 NOT NULL DEFAULT(SYSUTCDATETIME()));

CREATE TABLE dbo.instance_loginChange (
	rowId BIGINT NOT NULL IDENTITY(1,1) PRIMARY KEY,
	actionName NVARCHAR(128) NULL,
	principalName NVARCHAR(128) NULL,
	changeTimeUtc DATETIME2 NULL,
	targetPrincipalName NVARCHAR(128) NULL,
	targetPrincipalSid VARBINARY(85) NULL,
	targetRoleName NVARCHAR(128) NULL,
	targetRoleSid VARBINARY(85) NULL,
	changeStatementText NVARCHAR(4000) NULL,
	recordedUtc datetime2 NOT NULL DEFAULT(SYSUTCDATETIME()));

CREATE TABLE dbo.instance_privilegedRoleChange (
	rowId BIGINT NOT NULL IDENTITY(1,1) PRIMARY KEY,
	actionName NVARCHAR(128) NULL,
	principalName NVARCHAR(128) NULL,
	changeTimeUtc DATETIME2 NULL,
	targetPrincipalName NVARCHAR(128) NULL,
	targetPrincipalSid VARBINARY(85) NULL,
	targetRoleName NVARCHAR(128) NULL,
	targetRoleSid VARBINARY(85) NULL,
	changeStatementText NVARCHAR(4000) NULL,
	recordedUtc datetime2 NOT NULL DEFAULT(SYSUTCDATETIME()));
GO