/*

	Copyright (c) 2020 Ed Leighton-Dick
	
	License: https://edleightondick.com/about/legal-notices/#license

*/
USE [master]
GO

CREATE SERVER AUDIT [SecurityCollector]
	TO FILE 
	(	FILEPATH = N'C:\Temp\SqlAudit'
		,MAXSIZE = 50 MB
		,MAX_ROLLOVER_FILES = 10
		,RESERVE_DISK_SPACE = OFF
	)
	WITH
	(	QUEUE_DELAY = 1000
		,ON_FAILURE = CONTINUE
	)
	WHERE server_principal_name NOT LIKE 'NT SERVICE\%';
GO

CREATE SERVER AUDIT SPECIFICATION [SecurityCollector_Connections]
	FOR SERVER AUDIT [SecurityCollector]
	ADD (SUCCESSFUL_LOGIN_GROUP),
	ADD (FAILED_LOGIN_GROUP)
	WITH (STATE = OFF);
GO

ALTER SERVER AUDIT SPECIFICATION [SecurityCollector_Connections]
	WITH (STATE = ON);
ALTER SERVER AUDIT [SecurityCollector]
	WITH (STATE = ON);
GO

-- Create the procedures to read the SQL Audit logs
USE [SecurityCollector];
GO

CREATE OR ALTER PROCEDURE dbo.captureAudits (@debugMode BIT = 0)
AS BEGIN
	DECLARE @path NVARCHAR(260),
			@lastFile NVARCHAR(260),
			@lastOffset BIGINT;
	SELECT TOP(1) @path = log_file_path FROM sys.server_file_audits WHERE name = 'SecurityCollector';
	SELECT TOP(1) @lastFile = lastFile, @lastOffset = lastOffset FROM dbo.audit_bookmark WHERE auditName = 'SecurityCollector';

	SELECT af.event_time,
           af.action_id,
		   aa.name AS action_name,
           af.succeeded,
           af.session_id,
           af.server_principal_id,
           af.target_server_principal_id,
           af.object_id,
           af.class_type,
		   aa.class_desc,
           af.session_server_principal_name,
           af.server_principal_name,
           af.server_principal_sid,
           af.database_principal_name,
           af.target_server_principal_name,
           af.target_server_principal_sid,
           af.target_database_principal_name,
           af.server_instance_name,
           af.database_name,
           af.schema_name,
           af.object_name,
           af.statement,
           af.additional_information,
           af.file_name,
           af.audit_file_offset,
           af.client_ip,
           af.application_name,
           af.host_name
		INTO #unprocessedAuditRecords
		FROM sys.fn_get_audit_file(@path + '\SecurityCollector_*.sqlaudit', @lastFile, @lastOffset) af
			LEFT OUTER JOIN sys.dm_audit_class_type_map ac ON ac.class_type = af.class_type
			LEFT OUTER JOIN sys.dm_audit_actions aa ON aa.action_id = af.action_id AND aa.class_desc = ac.class_type_desc;

	IF (@debugMode <> 1) BEGIN
		WITH XMLNAMESPACES(DEFAULT 'http://schemas.microsoft.com/sqlserver/2008/sqlaudit_data'),
			connectionAudits AS
				(SELECT action_name,
					   event_time,
					   succeeded,
					   server_principal_id,
					   server_principal_name,
					   server_principal_sid,
					   additional_information,
					   client_ip,
					   application_name,
					   host_name,
					   CAST(additional_information AS XML).value('(/action_info/state)[1]', 'int') AS failureState
					FROM #unprocessedAuditRecords
					WHERE class_desc = 'LOGIN')
		MERGE INTO dbo.instance_connections t
			USING connectionAudits s
				ON s.event_time = t.connectionTimeUtc AND s.server_principal_sid = t.principalSid
			WHEN NOT MATCHED BY TARGET THEN
				INSERT (principalName, principalId, principalSid, clientIp, clientName, clientApplication, connectionTimeUtc, connectionSucceeded, connectionFailureState)
					VALUES (s.server_principal_name, s.server_principal_id, s.server_principal_sid, s.client_ip, s.host_name, s.application_name, s.event_time, s.succeeded, s.failureState);

		SELECT @lastFile = LAST_VALUE(file_name) OVER(ORDER BY (SELECT NULL)),
			   @lastOffset = LAST_VALUE(audit_file_offset) OVER(ORDER BY (SELECT NULL))
			FROM #unprocessedAuditRecords;

		UPDATE dbo.audit_bookmark
			SET lastFile = NULL,
				lastOffset = NULL
			WHERE auditName = 'SecurityCollector';
	END ELSE BEGIN
		WITH XMLNAMESPACES(DEFAULT 'http://schemas.microsoft.com/sqlserver/2008/sqlaudit_data'),
			connectionAudits AS
				(SELECT action_name,
					   event_time,
					   succeeded,
					   server_principal_id,
					   server_principal_name,
					   server_principal_sid,
					   additional_information,
					   client_ip,
					   application_name,
					   host_name,
					   CAST(additional_information AS XML).value('(/action_info/state)[1]', 'int') AS failureState
					FROM #unprocessedAuditRecords
					WHERE class_desc = 'LOGIN')
		SELECT s.server_principal_name, s.server_principal_id, s.server_principal_sid, s.client_ip, s.host_name, s.application_name, s.event_time, s.succeeded, s.failureState
			FROM connectionAudits s;

		SELECT file_name, audit_file_offset
			FROM #unprocessedAuditRecords;

		SELECT TOP(1) LAST_VALUE(file_name) OVER(ORDER BY (SELECT NULL)) AS lastFile,
			   LAST_VALUE(audit_file_offset) OVER(ORDER BY (SELECT NULL)) AS lastOffset
			FROM #unprocessedAuditRecords;
    END;

	DROP TABLE #unprocessedAuditRecords;
END;
GO

EXECUTE dbo.captureAudits @debugMode = 1;
GO