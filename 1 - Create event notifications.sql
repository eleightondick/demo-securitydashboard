/*

	Copyright (c) 2020 Ed Leighton-Dick
	
	License: https://edleightondick.com/about/legal-notices/#license

*/
USE [SecurityCollector];

CREATE QUEUE SecurityCollector_LoginChangeNotificationQueue;

CREATE SERVICE SecurityCollector_LoginChangeNotificationService
	ON QUEUE SecurityCollector_LoginChangeNotificationQueue
	([http://schemas.microsoft.com/SQL/Notifications/PostEventNotification]);

CREATE ROUTE SecurityCollector_LoginChangeNotificationRoute
	WITH SERVICE_NAME = 'SecurityCollector_LoginChangeNotificationService',
		 ADDRESS = 'LOCAL';
GO

CREATE EVENT NOTIFICATION SecurityCollector_LoginChangeNotification
	ON SERVER
	FOR CREATE_LOGIN, ALTER_LOGIN, DROP_LOGIN
	TO SERVICE 'SecurityCollector_LoginChangeNotificationService', 'current database';
GO

CREATE QUEUE SecurityCollector_RoleChangeNotificationQueue;

CREATE SERVICE SecurityCollector_RoleChangeNotificationService
	ON QUEUE SecurityCollector_RoleChangeNotificationQueue
	([http://schemas.microsoft.com/SQL/Notifications/PostEventNotification]);

CREATE ROUTE SecurityColelctor_RoleChangeNotificationRoute
	WITH SERVICE_NAME = 'SecurityCollector_RoleChangeNotificationService',
		 ADDRESS = 'LOCAL';
GO

CREATE EVENT NOTIFICATION SecurityCollector_RoleChangeNotification
	ON SERVER
	FOR ADD_SERVER_ROLE_MEMBER
	TO SERVICE 'SecurityCollector_RoleChangeNotificationService', 'current database';
GO

CREATE OR ALTER PROCEDURE dbo.captureLoginChanges
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
				FROM dbo.SecurityCollector_LoginChangeNotificationQueue),
			TIMEOUT 5000;

		IF @@ROWCOUNT > 0 BEGIN
			SAVE TRANSACTION messageReceived;

			INSERT INTO dbo.instance_loginChange (actionName, principalName, changeTimeUtc, targetPrincipalName, targetPrincipalSid, targetRoleName, targetRoleSid, changeStatementText)
				VALUES (@message.value('(/EVENT_INSTANCE/EventType)[1]', 'nvarchar(128)'),
						@message.value('(/EVENT_INSTANCE/LoginName)[1]', 'nvarchar(128)'),
						@message.value('(/EVENT_INSTANCE/PostTime)[1]', 'datetime2') AT TIME ZONE dbo.currentTimezone() at TIME ZONE 'UTC',
						@message.value('(/EVENT_INSTANCE/ObjectName)[1]', 'nvarchar(128)'),
						@message.value('(/EVENT_INSTANCE/SID)[1]', 'varbinary(85)'),
						@message.value('(/EVENT_INSTANCE/RoleName)[1]', 'nvarchar(128)'),
						@message.value('(/EVENT_INSTANCE/RoleSID)[1]', 'varbinary(85)'),
						@message.value('(/EVENT_INSTANCE/TSQLCommand/CommandText)[1]', 'nvarchar(4000)'));
        END;
	END TRY
    BEGIN CATCH
		ROLLBACK TRANSACTION messageReceived;

		END CONVERSATION @handle
			WITH ERROR = 50000
					DESCRIPTION = 'Record capture failed';
	END CATCH;

	COMMIT TRANSACTION;
END;
GO

CREATE OR ALTER PROCEDURE dbo.captureRoleChanges
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
				FROM dbo.SecurityCollector_RoleChangeNotificationQueue),
			TIMEOUT 5000;

		IF @@ROWCOUNT > 0 BEGIN
			SAVE TRANSACTION messageReceived;

			INSERT INTO dbo.instance_privilegedRoleChange (actionName, principalName, changeTimeUtc, targetPrincipalName, targetPrincipalSid, targetRoleName, targetRoleSid, changeStatementText)
				VALUES (@message.value('(/EVENT_INSTANCE/EventType)[1]', 'nvarchar(128)'),
						@message.value('(/EVENT_INSTANCE/LoginName)[1]', 'nvarchar(128)'),
						@message.value('(/EVENT_INSTANCE/PostTime)[1]', 'datetime2') AT TIME ZONE dbo.currentTimezone() at TIME ZONE 'UTC',
						@message.value('(/EVENT_INSTANCE/ObjectName)[1]', 'nvarchar(128)'),
						@message.value('(/EVENT_INSTANCE/SID)[1]', 'varbinary(85)'),
						@message.value('(/EVENT_INSTANCE/RoleName)[1]', 'nvarchar(128)'),
						@message.value('(/EVENT_INSTANCE/RoleSID)[1]', 'varbinary(85)'),
						@message.value('(/EVENT_INSTANCE/TSQLCommand/CommandText)[1]', 'nvarchar(4000)'));
        END;
	END TRY
    BEGIN CATCH
		ROLLBACK TRANSACTION messageReceived;

		END CONVERSATION @handle
			WITH ERROR = 50000
					DESCRIPTION = 'Record capture failed';
	END CATCH;

	COMMIT TRANSACTION;
END;
GO

ALTER QUEUE dbo.SecurityCollector_LoginChangeNotificationQueue
	WITH ACTIVATION (STATUS = ON,
					 PROCEDURE_NAME = dbo.captureLoginChanges,
					 MAX_QUEUE_READERS = 1,
					 EXECUTE AS OWNER);
GO

ALTER QUEUE dbo.SecurityCollector_RoleChangeNotificationQueue
	WITH ACTIVATION (STATUS = ON,
					 PROCEDURE_NAME = dbo.captureRoleChanges,
					 MAX_QUEUE_READERS = 1,
					 EXECUTE AS OWNER);
GO
