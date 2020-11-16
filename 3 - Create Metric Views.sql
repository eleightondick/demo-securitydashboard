/*

	Copyright (c) 2020 Ed Leighton-Dick
	
	License: https://edleightondick.com/about/legal-notices/#license

*/
USE SecurityDashboard;
GO

CREATE OR ALTER VIEW pbi.instance_lastReboot
AS
	SELECT ROW_NUMBER() OVER(ORDER BY instanceName, rowId) AS rowId,
		   instanceName,
           lastRebootUtc
		FROM dbo.instance_lastReboot;
GO

CREATE OR ALTER VIEW pbi.logins_orphaned
AS
	SELECT instanceName,
		   SUM(CASE WHEN firstDiscoveredUtc >= DATEADD(DAY, -1, GETDATE()) THEN 1 ELSE 0 END) AS nbrLast1Day,
		   SUM(CASE WHEN firstDiscoveredUtc >= DATEADD(DAY, -7, GETDATE()) THEN 1 ELSE 0 END) AS nbrLast7Day,
		   SUM(CASE WHEN firstDiscoveredUtc >= DATEADD(DAY, -30, GETDATE()) THEN 1 ELSE 0 END) AS nbrLast30Day,
		   MAX(firstDiscoveredUtc) AS lastDiscoveredUtc
		FROM dbo.logins_orphaned
		WHERE sid IS NOT NULL
		GROUP BY instanceName;
GO

CREATE OR ALTER VIEW pbi.instance_certificates_expiration
AS
	SELECT instanceName,
		   databaseName,
		   SUM(CASE WHEN expiryDate < DATEADD(DAY, 1, GETDATE()) THEN 1 ELSE 0 END) AS nbrNext1Day,
		   SUM(CASE WHEN expiryDate < DATEADD(DAY, 7, GETDATE()) THEN 1 ELSE 0 END) AS nbrNext7Day,
		   SUM(CASE WHEN expiryDate < DATEADD(DAY, 30, GETDATE()) THEN 1 ELSE 0 END) AS nbrNext30Day
		FROM dbo.instance_certificates
		WHERE name IS NOT NULL
		GROUP BY instanceName, databaseName;
GO

CREATE OR ALTER VIEW pbi.instance_certificates_backup
AS
	SELECT instanceName,
		   databaseName,
		   SUM(CASE WHEN pvtKeyLastBackup < DATEADD(DAY, -90, GETDATE()) THEN 1 ELSE 0 END) AS nbr90Days,
		   SUM(CASE WHEN pvtKeyLastBackup IS NULL THEN 1 ELSE 0 END) AS nbrNoBackup
		FROM dbo.instance_certificates
		WHERE name IS NOT NULL
		GROUP BY instanceName, databaseName;
GO

CREATE OR ALTER VIEW pbi.instance_connections_byIp
AS
	SELECT instanceName,
		   clientIp,
		   COUNT(ISNULL(connectionSucceeded, 0)) AS connectionsAttempted,
		   SUM(CAST(ISNULL(connectionSucceeded, 0) AS TINYINT)) / COUNT(ISNULL(connectionSucceeded, 0)) * 100 AS percentSucceeded,
		   DATEPART(HOUR, ISNULL(connectionTimeUtc, recordedUtc)) AS connectionHourUtc
		FROM dbo.instance_connections
		WHERE clientIp IS NOT NULL
		GROUP BY instanceName, clientIp, DATEPART(HOUR, ISNULL(connectionTimeUtc, recordedUtc));
GO

CREATE OR ALTER VIEW pbi.instance_loginChange_byType
AS
	SELECT ROW_NUMBER() OVER(ORDER BY instanceName, rowId) AS rowId,
		   instanceName,
		   actionName AS changeType,
		   ISNULL(changeTimeUtc, recordedUtc) AS changeTimeUtc
		FROM dbo.instance_loginChange
		WHERE actionName IS NOT NULL;
GO

CREATE OR ALTER VIEW pbi.instance_privilegedRoleChange_byRole
AS
	SELECT ROW_NUMBER() OVER(ORDER BY instanceName, rowId) AS rowId,
		   instanceName,
		   targetRoleName,
		   ISNULL(changeTimeUtc, recordedUtc) AS changeTimeUtc
		FROM dbo.instance_privilegedRoleChange
		WHERE targetRoleName IS NOT NULL;
GO

CREATE OR ALTER VIEW pbi.instance
AS
	WITH allInstances AS
		(SELECT DISTINCT instanceName FROM pbi.instance_certificates_backup
			UNION
         SELECT DISTINCT instanceName FROM pbi.instance_certificates_expiration
			UNION
         SELECT DISTINCT instanceName FROM pbi.instance_connections_byIp
			UNION
         SELECT DISTINCT instanceName FROM pbi.instance_lastReboot
			UNION
         SELECT DISTINCT instanceName FROM pbi.instance_loginChange_byType
			UNION
         SELECT DISTINCT instanceName FROM pbi.instance_privilegedRoleChange_byRole
			UNION
         SELECT DISTINCT instanceName FROM pbi.logins_orphaned)
	SELECT instanceName
		FROM allInstances;
GO

GRANT SELECT ON SCHEMA::pbi TO powerBi_SecurityDashboard;
GO