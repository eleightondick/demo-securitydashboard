/*

	Copyright (c) 2020 Ed Leighton-Dick
	
	License: https://edleightondick.com/about/legal-notices/#license

*/
USE master;

IF EXISTS (SELECT 'x' FROM sys.databases WHERE name = 'SecurityDashboard')
	DROP DATABASE [SecurityDashboard];

CREATE DATABASE [SecurityDashboard];
GO

ALTER AUTHORIZATION ON DATABASE::[SecurityDashboard] TO sa;
GO

-- Enable Service Broker
-- Allow cross-database communication
--     NOTE: TRUSTWORTHY is not recommended for production use. Use dialog security instead.
ALTER DATABASE [SecurityDashboard]
	SET ENABLE_BROKER, TRUSTWORTHY ON;
GO

USE SecurityDashboard;
GO

CREATE MASTER KEY
	ENCRYPTION BY PASSWORD = 'Yw=DKfaopu2KPqfk';
GO

-- Enable TDE
CREATE DATABASE ENCRYPTION KEY
	WITH ALGORITHM = AES_256
	ENCRYPTION BY SERVER CERTIFICATE cerTDE;

ALTER DATABASE [SecurityDashboard]
	SET ENCRYPTION ON;
GO

CREATE SCHEMA pbi
	AUTHORIZATION dbo;
GO

CREATE TABLE dbo.logins_orphaned (
	instanceName sysname NOT NULL,
	rowId BIGINT NOT NULL,
	[sid] VARBINARY(85) NULL,
	ntLogin sysname NULL,
	firstDiscoveredUtc DATETIME2 NOT NULL,
	lastRecordedUtc DATETIME2 NOT NULL,
	CONSTRAINT PK_logins_orphaned PRIMARY KEY CLUSTERED (instanceName, rowId));

CREATE TABLE dbo.instance_lastReboot (
	instanceName sysname NOT NULL,
	rowId BIGINT NOT NULL,
	lastRebootUtc DATETIME2 NOT NULL,
	recordedUtc DATETIME2 NOT NULL,
	CONSTRAINT PK_instance_lastReboot PRIMARY KEY CLUSTERED (instanceName, rowId));

CREATE TABLE dbo.instance_certificates (
	instanceName sysname NOT NULL,
	rowId BIGINT NOT NULL,
	databaseName sysname NULL,
	name sysname NULL,
	keyLength INT NULL,
	expiryDate DATETIME NULL,
	pvtKeyEncryptionType NVARCHAR(60) NULL,
	pvtKeyLastBackup DATETIME2 NULL,
	lastRecordedUtc DATETIME2 NOT NULL,
	CONSTRAINT PK_instance_certificates PRIMARY KEY CLUSTERED (instanceName, rowId));

CREATE TABLE dbo.instance_connections (
	instanceName sysname NOT NULL,
	rowId BIGINT NOT NULL,
	principalName NVARCHAR(128) NULL,
	principalId INT NULL,
	principalSid VARBINARY(85) NULL,
	clientIp NVARCHAR(128) NULL,
	clientName NVARCHAR(128) NULL,
	clientApplication NVARCHAR(128) NULL,
	connectionTimeUtc DATETIME2 NULL,
	connectionSucceeded BIT NULL,
	connectionFailureState INT NULL,
	recordedUtc datetime2 NOT NULL,
	CONSTRAINT PK_instance_connections PRIMARY KEY CLUSTERED (instanceName, rowId));

CREATE TABLE dbo.instance_loginChange (
	instanceName sysname NOT NULL,
	rowId BIGINT NOT NULL,
	actionName NVARCHAR(128) NULL,
	principalName NVARCHAR(128) NULL,
	changeTimeUtc DATETIME2 NULL,
	targetPrincipalName NVARCHAR(128) NULL,
	targetPrincipalSid VARBINARY(85) NULL,
	targetRoleName NVARCHAR(128) NULL,
	targetRoleSid VARBINARY(85) NULL,
	changeStatementText NVARCHAR(4000) NULL,
	recordedUtc datetime2 NOT NULL,
	CONSTRAINT PK_instance_loginChange PRIMARY KEY CLUSTERED (instanceName, rowId));

CREATE TABLE dbo.instance_privilegedRoleChange (
	instanceName sysname NOT NULL,
	rowId BIGINT NOT NULL,
	actionName NVARCHAR(128) NULL,
	principalName NVARCHAR(128) NULL,
	changeTimeUtc DATETIME2 NULL,
	targetPrincipalName NVARCHAR(128) NULL,
	targetPrincipalSid VARBINARY(85) NULL,
	targetRoleName NVARCHAR(128) NULL,
	targetRoleSid VARBINARY(85) NULL,
	changeStatementText NVARCHAR(4000) NULL,
	recordedUtc datetime2 NOT NULL,
	CONSTRAINT PK_instance_privilegedRoleChange PRIMARY KEY CLUSTERED (instanceName, rowId));
GO
