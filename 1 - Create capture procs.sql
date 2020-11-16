/*

	Copyright (c) 2020 Ed Leighton-Dick
	
	License: https://edleightondick.com/about/legal-notices/#license

*/
USE [SecurityCollector];
GO

-- Non-existent Windows logins
CREATE OR ALTER PROCEDURE dbo.captureLoginsOrphaned (@debugMode BIT = 0)
AS BEGIN
	DECLARE @loginsOrphaned TABLE (
		SID VARBINARY(85) NULL,
		[NT Login] sysname NULL);

	INSERT INTO @loginsOrphaned (SID, [NT Login])
		EXECUTE sys.sp_validatelogins;

	IF (@debugMode <> 1) BEGIN
		MERGE INTO dbo.logins_orphaned t
			USING @loginsOrphaned s
				ON s.SID = t.sid AND s.[NT Login] = t.ntLogin
			WHEN NOT MATCHED BY TARGET
				THEN INSERT (sid, ntLogin)
						VALUES (s.SID, s.[NT Login])
			WHEN MATCHED
				THEN UPDATE
						SET t.lastRecordedUtc = SYSUTCDATETIME();
	END;
END;
GO

EXECUTE dbo.captureLoginsOrphaned @debugMode=1;
GO

-- Last reboot/Days since reboot
CREATE OR ALTER PROCEDURE dbo.captureLastReboot (@debugMode bit = 0)
AS BEGIN
	IF (@debugMode <> 1) BEGIN
		INSERT INTO dbo.instance_lastReboot (lastRebootUtc)
			SELECT sqlserver_start_time at TIME ZONE dbo.currentTimezone() at TIME ZONE 'UTC'
				FROM sys.dm_os_sys_info;
	END ELSE BEGIN
		SELECT sqlserver_start_time at TIME ZONE dbo.currentTimezone() at TIME ZONE 'UTC'
			FROM sys.dm_os_sys_info;
	END;
END;
GO

EXECUTE dbo.captureLastReboot @debugMode = 1;
GO

-- Expiring certificates
CREATE OR ALTER PROCEDURE dbo.captureCertificates (@debugMode BIT = 0)
AS BEGIN
	CREATE TABLE ##allCerts (
		database_name sysname NULL,
		name sysname NULL,
		key_length INT NULL,
		expiry_date DATETIME NULL,
		pvt_key_encryption_type_desc NVARCHAR(60) NULL,
		pvt_key_last_backup_date DATETIME NULL);

	EXECUTE sp_MSforeachdb 'insert into ##allCerts SELECT ''?'' AS database_name, name, key_length, expiry_date, pvt_key_encryption_type_desc, pvt_key_last_backup_date from ?.sys.certificates';
	
	IF (@debugMode <> 1) BEGIN
		MERGE INTO dbo.instance_certificates t
			USING ##allCerts s
				 ON s.database_name = t.databaseName AND s.name = t.name
			WHEN NOT MATCHED BY TARGET
				THEN INSERT (databaseName, name, keyLength, expiryDate, pvtKeyEncryptionType, pvtKeyLastBackup)
						VALUES (s.database_name, s.name, s.key_length, s.expiry_date, s.pvt_key_encryption_type_desc, s.pvt_key_last_backup_date)
			WHEN MATCHED
				THEN UPDATE
						SET t.keyLength = s.key_length,
							t.expiryDate = s.expiry_date,
							t.pvtKeyEncryptionType = s.pvt_key_encryption_type_desc,
							t.pvtKeyLastBackup = s.pvt_key_last_backup_date,
							t.lastRecordedUtc = SYSUTCDATETIME();
	END ELSE BEGIN
		SELECT database_name, name, key_length, expiry_date, pvt_key_encryption_type_desc, pvt_key_last_backup_date FROM ##allCerts;
    END;

	-- Clean up
	DROP TABLE ##allCerts;
END;
GO

EXECUTE dbo.captureCertificates @debugMode = 1;
GO

-- Create a job to run each of these procedures on a regular basis
USE [msdb]
GO

/****** Object:  Job [SecurityCollector - Capture]    Script Date: 11/12/2020 7:16:10 PM ******/
BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0
/****** Object:  JobCategory [Database Maintenance]    Script Date: 11/12/2020 7:16:10 PM ******/
IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'Database Maintenance' AND category_class=1)
BEGIN
EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'Database Maintenance'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'SecurityCollector - Capture', 
		@enabled=1, 
		@notify_level_eventlog=0, 
		@notify_level_email=0, 
		@notify_level_netsend=0, 
		@notify_level_page=0, 
		@delete_level=0, 
		@category_name=N'Database Maintenance', 
		@owner_login_name=N'sa', @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Capture orphaned logins]    Script Date: 11/12/2020 7:16:10 PM ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'Capture orphaned logins', 
		@step_id=1, 
		@cmdexec_success_code=0, 
		@on_success_action=3, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'TSQL', 
		@command=N'EXECUTE dbo.captureLoginsOrphaned;', 
		@database_name=N'SecurityCollector', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Capture certificates]    Script Date: 11/12/2020 7:16:10 PM ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'Capture certificates', 
		@step_id=2, 
		@cmdexec_success_code=0, 
		@on_success_action=1, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'TSQL', 
		@command=N'EXECUTE dbo.captureCertificates;', 
		@database_name=N'SecurityCollector', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'SecurityCollector - Daily', 
		@enabled=1, 
		@freq_type=4, 
		@freq_interval=1, 
		@freq_subday_type=1, 
		@freq_subday_interval=0, 
		@freq_relative_interval=0, 
		@freq_recurrence_factor=0, 
		@active_start_date=20201109, 
		@active_end_date=99991231, 
		@active_start_time=0, 
		@active_end_time=235959, 
		@schedule_uid=N'4db2930c-b380-4ea0-997f-a3598ec2e37e'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
    IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:
GO

/****** Object:  Job [SecurityCollector - Capture on restart]    Script Date: 11/12/2020 5:59:53 PM ******/
BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0
/****** Object:  JobCategory [Database Maintenance]    Script Date: 11/12/2020 5:59:53 PM ******/
IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'Database Maintenance' AND category_class=1)
BEGIN
EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'Database Maintenance'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'SecurityCollector - Capture on restart', 
		@enabled=1, 
		@notify_level_eventlog=0, 
		@notify_level_email=0, 
		@notify_level_netsend=0, 
		@notify_level_page=0, 
		@delete_level=0, 
		@description=N'No description available.', 
		@category_name=N'Database Maintenance', 
		@owner_login_name=N'sa', @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Capture last reboot]    Script Date: 11/12/2020 5:59:53 PM ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'Capture last reboot', 
		@step_id=1, 
		@cmdexec_success_code=0, 
		@on_success_action=1, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'TSQL', 
		@command=N'EXECUTE dbo.captureLastReboot;', 
		@database_name=N'SecurityCollector', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'SecurityCollector - On Restart', 
		@enabled=1, 
		@freq_type=64, 
		@freq_interval=0, 
		@freq_subday_type=0, 
		@freq_subday_interval=0, 
		@freq_relative_interval=0, 
		@freq_recurrence_factor=0, 
		@active_start_date=20201112, 
		@active_end_date=99991231, 
		@active_start_time=0, 
		@active_end_time=235959, 
		@schedule_uid=N'511fd7db-693d-41d3-a673-a47aa649d6a6'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
    IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:
GO

/****** Object:  Job [SecurityCollector - Capture audits]    Script Date: 11/12/2020 7:18:26 PM ******/
BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0
/****** Object:  JobCategory [Database Maintenance]    Script Date: 11/12/2020 7:18:26 PM ******/
IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'Database Maintenance' AND category_class=1)
BEGIN
EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'Database Maintenance'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'SecurityCollector - Capture audits', 
		@enabled=1, 
		@notify_level_eventlog=0, 
		@notify_level_email=0, 
		@notify_level_netsend=0, 
		@notify_level_page=0, 
		@delete_level=0, 
		@description=N'No description available.', 
		@category_name=N'Database Maintenance', 
		@owner_login_name=N'sa', @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Capture audits]    Script Date: 11/12/2020 7:18:26 PM ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'Capture audits', 
		@step_id=1, 
		@cmdexec_success_code=0, 
		@on_success_action=1, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'TSQL', 
		@command=N'EXECUTE dbo.captureAudits;', 
		@database_name=N'SecurityCollector', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'SecurityCollector - Every 2 minutes', 
		@enabled=1, 
		@freq_type=4, 
		@freq_interval=1, 
		@freq_subday_type=4, 
		@freq_subday_interval=2, 
		@freq_relative_interval=0, 
		@freq_recurrence_factor=0, 
		@active_start_date=20201112, 
		@active_end_date=20201114, 
		@active_start_time=100, 
		@active_end_time=235959, 
		@schedule_uid=N'511fd7db-693d-41d3-a673-a47aa649d6a6'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
    IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:
GO

