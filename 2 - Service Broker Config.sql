/*

	Copyright (c) 2020 Ed Leighton-Dick
	
	License: https://edleightondick.com/about/legal-notices/#license

*/
USE SecurityCollector;

-- Only required when target is on a different server
--CREATE ENDPOINT brokerEndpoint
--	AS TCP (LISTENER_PORT = 4022)
--	FOR SERVICE_BROKER
--		(AUTHENTICATION = WINDOWS NEGOTIATE,
--		 ENCRYPTION = DISABLED,
--		 MESSAGE_FORWARDING = DISABLED);
--GRANT CONNECT ON ENDPOINT::brokerEndpoint TO [AD\myLogin];

CREATE MESSAGE TYPE [//securitydashboard/ack]
	VALIDATION = EMPTY;
CREATE MESSAGE TYPE [//securitydashboard/certificate]
	VALIDATION = WELL_FORMED_XML;
CREATE MESSAGE TYPE [//securitydashboard/connection]
	VALIDATION = WELL_FORMED_XML;
CREATE MESSAGE TYPE [//securitydashboard/lastReboot]
	VALIDATION = WELL_FORMED_XML;
CREATE MESSAGE TYPE [//securitydashboard/loginChange]
	VALIDATION = WELL_FORMED_XML;
CREATE MESSAGE TYPE [//securitydashboard/privilegedRoleChange]
	VALIDATION = WELL_FORMED_XML;
CREATE MESSAGE TYPE [//securitydashboard/orphanedLogin]
	VALIDATION = WELL_FORMED_XML;

CREATE CONTRACT [//securitydashboard/contract]
	([//securitydashboard/certificate] SENT BY INITIATOR,
	 [//securitydashboard/connection] SENT BY INITIATOR,
	 [//securitydashboard/lastReboot] SENT BY INITIATOR,
	 [//securitydashboard/loginChange] SENT BY INITIATOR,
	 [//securitydashboard/privilegedRoleChange] SENT BY INITIATOR,
	 [//securitydashboard/orphanedLogin] SENT BY INITIATOR,
	 [//securitydashboard/ack] SENT BY TARGET);
CREATE QUEUE [CollectorQueue]
	WITH STATUS = ON;
CREATE SERVICE [//securitydashboard/collectorService]
	ON QUEUE [CollectorQueue] ([//securitydashboard/contract]);

CREATE ROUTE [ToDashboard]
	WITH SERVICE_NAME = '//securitydashboard/dashboardService',
		 ADDRESS = 'LOCAL';
GO

USE SecurityDashboard;

-- Only required when initiator is on a different server
--CREATE ENDPOINT brokerEndpoint
--	AS TCP (LISTENER_PORT = 4022)
--	FOR SERVICE_BROKER
--		(AUTHENTICATION = WINDOWS NEGOTIATE,
--		 ENCRYPTION = DISABLED,
--		 MESSAGE_FORWARDING = DISABLED);
--GRANT CONNECT ON ENDPOINT::brokerEndpoint TO [AD\myLogin];

CREATE MESSAGE TYPE [//securitydashboard/ack]
	VALIDATION = EMPTY;
CREATE MESSAGE TYPE [//securitydashboard/certificate]
	VALIDATION = WELL_FORMED_XML;
CREATE MESSAGE TYPE [//securitydashboard/connection]
	VALIDATION = WELL_FORMED_XML;
CREATE MESSAGE TYPE [//securitydashboard/lastReboot]
	VALIDATION = WELL_FORMED_XML;
CREATE MESSAGE TYPE [//securitydashboard/loginChange]
	VALIDATION = WELL_FORMED_XML;
CREATE MESSAGE TYPE [//securitydashboard/privilegedRoleChange]
	VALIDATION = WELL_FORMED_XML;
CREATE MESSAGE TYPE [//securitydashboard/orphanedLogin]
	VALIDATION = WELL_FORMED_XML;

CREATE CONTRACT [//securitydashboard/contract]
	([//securitydashboard/certificate] SENT BY INITIATOR,
	 [//securitydashboard/connection] SENT BY INITIATOR,
	 [//securitydashboard/lastReboot] SENT BY INITIATOR,
	 [//securitydashboard/loginChange] SENT BY INITIATOR,
	 [//securitydashboard/privilegedRoleChange] SENT BY INITIATOR,
	 [//securitydashboard/orphanedLogin] SENT BY INITIATOR,
	 [//securitydashboard/ack] SENT BY TARGET);
CREATE QUEUE [DashboardQueue]
	WITH STATUS = ON;
CREATE SERVICE [//securitydashboard/dashboardService]
	ON QUEUE [DashboardQueue] ([//securitydashboard/contract]);

-- Only required when initiator is on a different server
--GRANT SEND ON SERVICE::[//securitydashboard/dashboardService] TO PUBLIC;

CREATE ROUTE [ToCollector]
	WITH SERVICE_NAME = '//securitydashboard/collectorService',
		 ADDRESS = 'LOCAL';
GO

-- When using multiple servers, dialog security is also recommended

USE SecurityCollector;
GO

CREATE OR ALTER PROCEDURE dbo.sendToDashboard_certificate (@auditInfo XML)
AS BEGIN
	DECLARE @dialogHandle UNIQUEIDENTIFIER;

	BEGIN DIALOG CONVERSATION @dialogHandle
		FROM SERVICE [//securitydashboard/collectorService]
		TO SERVICE '//securitydashboard/dashboardService'
		ON CONTRACT [//securitydashboard/contract];

	SEND ON CONVERSATION @dialogHandle
		MESSAGE TYPE [//securitydashboard/certificate]
		(@auditInfo);
END;
GO

CREATE OR ALTER PROCEDURE dbo.sendToDashboard_connection (@auditInfo XML)
AS BEGIN
	DECLARE @dialogHandle UNIQUEIDENTIFIER;

	BEGIN DIALOG CONVERSATION @dialogHandle
		FROM SERVICE [//securitydashboard/collectorService]
		TO SERVICE '//securitydashboard/dashboardService'
		ON CONTRACT [//securitydashboard/contract];

	SEND ON CONVERSATION @dialogHandle
		MESSAGE TYPE [//securitydashboard/connection]
		(@auditInfo);
END;
GO

CREATE OR ALTER PROCEDURE dbo.sendToDashboard_lastReboot (@auditInfo XML)
AS BEGIN
	DECLARE @dialogHandle UNIQUEIDENTIFIER;

	BEGIN DIALOG CONVERSATION @dialogHandle
		FROM SERVICE [//securitydashboard/collectorService]
		TO SERVICE '//securitydashboard/dashboardService'
		ON CONTRACT [//securitydashboard/contract];

	SEND ON CONVERSATION @dialogHandle
		MESSAGE TYPE [//securitydashboard/lastReboot]
		(@auditInfo);
END;
GO

CREATE OR ALTER PROCEDURE dbo.sendToDashboard_loginChange (@auditInfo XML)
AS BEGIN
	DECLARE @dialogHandle UNIQUEIDENTIFIER;

	BEGIN DIALOG CONVERSATION @dialogHandle
		FROM SERVICE [//securitydashboard/collectorService]
		TO SERVICE '//securitydashboard/dashboardService'
		ON CONTRACT [//securitydashboard/contract];

	SEND ON CONVERSATION @dialogHandle
		MESSAGE TYPE [//securitydashboard/loginChange]
		(@auditInfo);
END;
GO

CREATE OR ALTER PROCEDURE dbo.sendToDashboard_privilegedRoleChange (@auditInfo XML)
AS BEGIN
	DECLARE @dialogHandle UNIQUEIDENTIFIER;

	BEGIN DIALOG CONVERSATION @dialogHandle
		FROM SERVICE [//securitydashboard/collectorService]
		TO SERVICE '//securitydashboard/dashboardService'
		ON CONTRACT [//securitydashboard/contract];

	SEND ON CONVERSATION @dialogHandle
		MESSAGE TYPE [//securitydashboard/privilegedRoleChange]
		(@auditInfo);
END;
GO

CREATE OR ALTER PROCEDURE dbo.sendToDashboard_orphanedLogin (@auditInfo XML)
AS BEGIN
	DECLARE @dialogHandle UNIQUEIDENTIFIER;

	BEGIN DIALOG CONVERSATION @dialogHandle
		FROM SERVICE [//securitydashboard/collectorService]
		TO SERVICE '//securitydashboard/dashboardService'
		ON CONTRACT [//securitydashboard/contract];

	SEND ON CONVERSATION @dialogHandle
		MESSAGE TYPE [//securitydashboard/orphanedLogin]
		(@auditInfo);
END;
GO

USE SecurityDashboard;
GO

CREATE OR ALTER PROCEDURE dbo.record_certificate  (@auditInfo XML)
AS BEGIN
	DECLARE @hdoc INT;
	EXECUTE sp_xml_preparedocument @hdoc OUTPUT, @auditInfo;

	INSERT INTO dbo.instance_certificates (instanceName, rowId, databaseName, name, keyLength, expiryDate, pvtKeyEncryptionType, pvtKeyLastBackup, lastRecordedUtc)
		SELECT instanceName,
			   rowId,
			   databaseName,
			   name,
			   keyLength,
			   expiryDate,
			   pvtKeyEncryptionType,
			   pvtKeyLastBackup,
			   lastRecordedUtc
			FROM OPENXML(@hdoc, '/certificate', 1)
			WITH (instanceName sysname,
				  rowId BIGINT,
				  databaseName sysname,
				  name sysname,
				  keyLength INT,
				  expiryDate DATETIME,
				  pvtKeyEncryptionType NVARCHAR(60),
				  pvtKeyLastBackup DATETIME2,
				  lastRecordedUtc DATETIME2);
END;
GO

CREATE OR ALTER PROCEDURE dbo.record_connection  (@auditInfo XML)
AS BEGIN
	DECLARE @hdoc INT;
	EXECUTE sp_xml_preparedocument @hdoc OUTPUT, @auditInfo;

	INSERT INTO dbo.instance_connections (instanceName, rowId, principalName, principalId, principalSid, clientIp, clientName, clientApplication, connectionTimeUtc, connectionSucceeded, connectionFailureState, recordedUtc)
		SELECT instanceName,
			   rowId,
			   principalName,
			   principalId,
			   CONVERT(VARBINARY(85), principalSid, 1) principalSid,
			   clientIp,
			   clientName,
			   clientApplication,
			   connectionTimeUtc,
			   connectionSucceeded,
			   connectionFailureState,
			   recordedUtc
			FROM OPENXML(@hdoc, '/connection', 1)
			WITH (instanceName sysname,
				  rowId BIGINT,
				  principalName NVARCHAR(128),
				  principalId INT,
				  principalSid VARCHAR(58),
				  clientIp NVARCHAR(128),
				  clientName NVARCHAR(128),
				  clientApplication NVARCHAR(128),
				  connectionTimeUtc DATETIME2,
				  connectionSucceeded BIT,
				  connectionFailureState INT,
				  recordedUtc DATETIME2);
END;
GO

CREATE OR ALTER PROCEDURE dbo.record_lastReboot  (@auditInfo XML)
AS BEGIN
	DECLARE @hdoc INT;
	EXECUTE sp_xml_preparedocument @hdoc OUTPUT, @auditInfo;
	
	INSERT INTO dbo.instance_lastReboot (instanceName, rowId, lastRebootUtc, recordedUtc)
		SELECT instanceName,
               rowId,
               lastRebootUtc,
               recordedUtc
			FROM OPENXML(@hdoc, '/lastReboot', 1)
			WITH (instanceName sysname,
				  rowId BIGINT,
				  lastRebootUtc DATETIME2,
				  recordedUtc DATETIME2);
END;
GO

CREATE OR ALTER PROCEDURE dbo.record_loginChange  (@auditInfo XML)
AS BEGIN
	DECLARE @hdoc INT;
	EXECUTE sp_xml_preparedocument @hdoc OUTPUT, @auditInfo;

	INSERT INTO dbo.instance_loginChange (instanceName, rowId, actionName, principalName, changeTimeUtc, targetPrincipalName, targetPrincipalSid, targetRoleName, targetRoleSid, changeStatementText, recordedUtc)
		SELECT instanceName,
               rowId,
               actionName,
               principalName,
               changeTimeUtc,
               targetPrincipalName,
               CONVERT(VARBINARY(85), targetPrincipalSid, 1) targetPrincipalSid,
               targetRoleName,
               CONVERT(VARBINARY(85), targetRoleSid, 1) targetRoleSid,
               changeStatementText,
               recordedUtc
			FROM OPENXML(@hdoc, '/loginChange', 1)
			WITH (instanceName sysname,
				  rowId BIGINT,
				  actionName NVARCHAR(128),
				  principalName NVARCHAR(128),
				  changeTimeUtc DATETIME2,
				  targetPrincipalName NVARCHAR(128),
				  targetPrincipalSid VARCHAR(58),
				  targetRoleName NVARCHAR(128),
				  targetRoleSid VARCHAR(58),
				  changeStatementText NVARCHAR(4000),
				  recordedUtc DATETIME2);
END;
GO

CREATE OR ALTER PROCEDURE dbo.record_privilegedRoleChange  (@auditInfo XML)
AS BEGIN
	DECLARE @hdoc INT;
	EXECUTE sp_xml_preparedocument @hdoc OUTPUT, @auditInfo;

	INSERT INTO dbo.instance_privilegedRoleChange (instanceName, rowId, actionName, principalName, changeTimeUtc, targetPrincipalName, targetPrincipalSid, targetRoleName, targetRoleSid, changeStatementText, recordedUtc)
		SELECT instanceName,
               rowId,
               actionName,
               principalName,
               changeTimeUtc,
               targetPrincipalName,
               CONVERT(VARBINARY(85), targetPrincipalSid, 1) targetPrincipalSid,
               targetRoleName,
               CONVERT(VARBINARY(85), targetRoleSid, 1) targetRoleSid,
               changeStatementText,
               recordedUtc
			FROM OPENXML(@hdoc, '/privilegedRoleChange', 1)
			WITH (instanceName sysname,
				  rowId BIGINT,
				  actionName NVARCHAR(128),
				  principalName NVARCHAR(128),
				  changeTimeUtc DATETIME2,
				  targetPrincipalName NVARCHAR(128),
				  targetPrincipalSid VARCHAR(58),
				  targetRoleName NVARCHAR(128),
				  targetRoleSid VARCHAR(58),
				  changeStatementText NVARCHAR(128),
				  recordedUtc DATETIME2);
END;
GO

CREATE OR ALTER PROCEDURE dbo.record_orphanedLogin  (@auditInfo XML)
AS BEGIN
	DECLARE @hdoc INT;
	EXECUTE sp_xml_preparedocument @hdoc OUTPUT, @auditInfo;

	INSERT INTO dbo.logins_orphaned (instanceName, rowId, sid, ntLogin, firstDiscoveredUtc, lastRecordedUtc)
		SELECT instanceName,
               rowId,
               CONVERT(VARBINARY(85), sid, 1) sid,
               ntLogin,
               firstDiscoveredUtc,
               lastRecordedUtc
			FROM OPENXML(@hdoc, '/orphanedLogin', 1)
			WITH (instanceName sysname,
				  rowId BIGINT,
				  sid VARCHAR(58),
				  ntLogin sysname,
				  firstDiscoveredUtc DATETIME2,
				  lastRecordedUtc DATETIME2);
END;
GO

CREATE OR ALTER PROCEDURE dbo.receiveFromCollector
AS BEGIN
	DECLARE @handle UNIQUEIDENTIFIER,
			@messageType NVARCHAR(256),
			@message XML;

	BEGIN TRY
		BEGIN TRANSACTION;

		WAITFOR (
			RECEIVE TOP(1) @handle = conversation_handle,
							@messageType = message_type_name,
							@message = CAST(message_body AS XML)
				FROM dbo.DashboardQueue),
			TIMEOUT 5000;

		IF @@ROWCOUNT > 0 BEGIN
			SAVE TRANSACTION messageReceived;

			IF @messageType = '//securitydashboard/certificate'
				EXECUTE dbo.record_certificate @message;
			ELSE IF @messageType = '//securitydashboard/connection'
				EXECUTE dbo.record_connection @message;
			ELSE IF @messageType = '//securitydashboard/lastReboot'
				EXECUTE dbo.record_lastReboot @message;
			ELSE IF @messageType = '//securitydashboard/loginChange'
				EXECUTE dbo.record_loginChange @message;
			ELSE IF @messageType = '//securitydashboard/privilegedRoleChange'
				EXECUTE dbo.record_privilegedRoleChange @message;
			ELSE IF @messageType = '//securitydashboard/orphanedLogin'
				EXECUTE dbo.record_orphanedLogin @message;
			ELSE
				RAISERROR('Invalid message type', 16, 1);

			SEND ON CONVERSATION @handle
				MESSAGE TYPE [//securitydashboard/ack];
			END CONVERSATION @handle;
        END;
	END TRY
    BEGIN CATCH
		ROLLBACK TRANSACTION messageReceived;

		DECLARE @errorMessage NVARCHAR(4000) = 'Receive failed - ' + ERROR_MESSAGE();

		END CONVERSATION @handle
			WITH ERROR = 50000
				 DESCRIPTION = @errorMessage;
	END CATCH;

	COMMIT TRANSACTION;
END;
GO

ALTER QUEUE [DashboardQueue]
	WITH ACTIVATION (STATUS = ON,
					 PROCEDURE_NAME = dbo.receiveFromCollector,
					 MAX_QUEUE_READERS = 1,
					 EXECUTE AS OWNER);
GO

USE SecurityCollector;
GO

CREATE OR ALTER TRIGGER trgI_certificates
	ON dbo.instance_certificates
	AFTER INSERT
AS BEGIN
	DECLARE @auditInfo XML;

	-- A cursor is used here to properly handle multi-record inserts
	-- Constraining to STATIC READ_ONLY to minimize impact, LOCAL to prevent multi-session conflicts
	DECLARE cRows CURSOR LOCAL STATIC READ_ONLY FOR
		SELECT Inserted.rowId,
               Inserted.databaseName,
               Inserted.name,
               Inserted.keyLength,
               Inserted.expiryDate,
               Inserted.pvtKeyEncryptionType,
               Inserted.pvtKeyLastBackup,
               Inserted.lastRecordedUtc
			FROM Inserted;
		DECLARE @rowId INT,
				@databaseName sysname,
				@name sysname,
				@keyLength INT,
				@expiryDate DATETIME,
				@pvtKeyEncryptionType NVARCHAR(60),
				@pvtKeyLastBackup DATETIME2,
				@lastRecordedUtc DATETIME2;

	OPEN cRows;
	FETCH NEXT FROM cRows INTO @rowId, @databaseName, @name, @keyLength, @expiryDate, @pvtKeyEncryptionType, @pvtKeyLastBackup, @lastRecordedUtc;

	WHILE (@@FETCH_STATUS = 0) BEGIN
		SET @auditInfo =
			(SELECT @@SERVERNAME AS instanceName,
					@rowId AS rowId,
					@databaseName AS databaseName,
					@name AS name,
					@keyLength AS keyLength,
					@expiryDate AS expiryDate,
					@pvtKeyEncryptionType AS pvtKeyEncryptionType,
					@pvtKeyLastBackup AS pvtKeyLastBackup,
					@lastRecordedUtc AS lastRecordedUtc
				FOR XML RAW ('certificate'));
		EXECUTE dbo.sendToDashboard_certificate @auditInfo;

		FETCH NEXT FROM cRows INTO @rowId, @databaseName, @name, @keyLength, @expiryDate, @pvtKeyEncryptionType, @pvtKeyLastBackup, @lastRecordedUtc;
	END;

	CLOSE cRows;
	DEALLOCATE cRows;
END;
GO

CREATE OR ALTER TRIGGER trgI_connections
	ON dbo.instance_connections
	AFTER INSERT
AS BEGIN
	DECLARE @auditInfo XML;

	-- A cursor is used here to properly handle multi-record inserts
	-- Constraining to STATIC READ_ONLY to minimize impact, LOCAL to prevent multi-session conflicts
	DECLARE cRows CURSOR LOCAL STATIC READ_ONLY FOR
		SELECT Inserted.rowId,
               Inserted.principalName,
               Inserted.principalId,
               Inserted.principalSid,
               Inserted.clientIp,
               Inserted.clientName,
               Inserted.clientApplication,
               Inserted.connectionTimeUtc,
               Inserted.connectionSucceeded,
               Inserted.connectionFailureState,
               Inserted.recordedUtc
			FROM Inserted;
	DECLARE @rowId BIGINT,
			@principalName NVARCHAR(128),
			@principalId INT,
			@principalSid VARBINARY(85),
			@clientIp NVARCHAR(128),
			@clientName NVARCHAR(128),
			@clientApplication NVARCHAR(128),
			@connectionTimeUtc DATETIME2,
			@connectionSucceeded BIT,
			@connectionFailureState INT,
			@recordedUtc DATETIME2;

	OPEN cRows;
	FETCH NEXT FROM cRows INTO @rowId, @principalName, @principalId, @principalSid, @clientIp, @clientName, @clientApplication, @connectionTimeUtc, @connectionSucceeded, @connectionFailureState, @recordedUtc;

	WHILE @@FETCH_STATUS = 0 BEGIN
		SET @auditInfo =
			(SELECT @@SERVERNAME AS instanceName,
					@rowId AS rowId,
					@principalName AS principalName,
					@principalId AS principalId,
					CONVERT(VARCHAR(58), @principalSid, 1) AS principalSid,
					@clientIp AS clientIp,
					@clientName AS clientName,
					@clientApplication AS clientApplication,
					@connectionTimeUtc AS connectionTimeUtc,
					@connectionSucceeded AS connectionSucceeded,
					@connectionFailureState AS connectionFailureState,
					@recordedUtc AS recordedUtc
				FOR XML RAW ('connection'));
		EXECUTE dbo.sendToDashboard_connection @auditInfo;

		FETCH NEXT FROM cRows INTO @rowId, @principalName, @principalId, @principalSid, @clientIp, @clientName, @clientApplication, @connectionTimeUtc, @connectionSucceeded, @connectionFailureState, @recordedUtc;
	END;

	CLOSE cRows;
	DEALLOCATE cRows;
END;
GO

CREATE OR ALTER TRIGGER trgI_lastReboot
	ON dbo.instance_lastReboot
	AFTER INSERT
AS BEGIN
	DECLARE @auditInfo XML;

	SET @auditInfo =
		(SELECT @@SERVERNAME instanceName,
			    Inserted.rowId,
                Inserted.lastRebootUtc,
                Inserted.recordedUtc
			FROM inserted
			FOR XML RAW ('lastReboot'));
	EXECUTE dbo.sendToDashboard_lastReboot @auditInfo;
END;
GO

CREATE OR ALTER TRIGGER trgI_loginChange
	ON dbo.instance_loginChange
	AFTER INSERT
AS BEGIN
	DECLARE @auditInfo XML;

	SET @auditInfo =
		(SELECT @@SERVERNAME instanceName,
			    Inserted.rowId,
                Inserted.actionName,
                Inserted.principalName,
                Inserted.changeTimeUtc,
                Inserted.targetPrincipalName,
                CONVERT(VARCHAR(58), Inserted.targetPrincipalSid, 1) targetPrincipalSid,
                Inserted.targetRoleName,
                CONVERT(VARCHAR(58), Inserted.targetRoleSid, 1) targetRoleSid,
                Inserted.changeStatementText,
                Inserted.recordedUtc
			FROM inserted
			FOR XML RAW ('loginChange'));
	EXECUTE dbo.sendToDashboard_loginChange @auditInfo;
END;
GO

CREATE OR ALTER TRIGGER trgI_privilegedRoleChange
	ON dbo.instance_privilegedRoleChange
	AFTER INSERT
AS BEGIN
	DECLARE @auditInfo XML;

	SET @auditInfo =
		(SELECT @@SERVERNAME instanceName,
			    Inserted.rowId,
                Inserted.actionName,
                Inserted.principalName,
                Inserted.changeTimeUtc,
                Inserted.targetPrincipalName,
                CONVERT(VARCHAR(58), Inserted.targetPrincipalSid, 1) targetPrincipalSid,
                Inserted.targetRoleName,
                CONVERT(VARCHAR(58), Inserted.targetRoleSid, 1) targetRoleSid,
                Inserted.changeStatementText,
                Inserted.recordedUtc
			FROM inserted
			FOR XML RAW ('privilegedRoleChange'));
	EXECUTE dbo.sendToDashboard_privilegedRoleChange @auditInfo;
END;
GO

CREATE OR ALTER TRIGGER trgI_orphanedLogins
	ON dbo.logins_orphaned
	AFTER INSERT
AS BEGIN
	DECLARE @auditInfo XML;

	SET @auditInfo =
		(SELECT @@SERVERNAME instanceName,
			    Inserted.rowId,
                CONVERT(VARCHAR(58), Inserted.sid, 1) sid,
                Inserted.ntLogin,
                Inserted.firstDiscoveredUtc,
                Inserted.lastRecordedUtc
			FROM inserted
			FOR XML RAW ('orphanedLogins'));
	EXECUTE dbo.sendToDashboard_orphanedLogin @auditInfo;
END;
GO

