-- Dirty Frag exposure hunting queries for osquery.
-- Run with osqueryi/osqueryd on Linux hosts. These queries are read-only.

-- Loaded watched modules.
SELECT name, size, used_by, status
FROM kernel_modules
WHERE name IN ('esp4', 'esp6', 'rxrpc');

-- Common modprobe temporary mitigations.
SELECT path, key, value
FROM kernel_info
WHERE key = 'release';

SELECT path, filename, size, mtime
FROM file
WHERE path IN (
  '/etc/modprobe.d/dirtyfrag.conf',
  '/etc/modprobe.d/disable-dirtyfrag.conf'
);

-- Suspicious writable staging locations for Linux exploit artifacts.
SELECT path, filename, uid, gid, mode, size, mtime, ctime
FROM file
WHERE (
  path LIKE '/tmp/%' OR
  path LIKE '/var/tmp/%' OR
  path LIKE '/dev/shm/%' OR
  path LIKE '/run/user/%'
)
AND (
  filename IN ('update', 'dirtyfrag', 'dirty_frag', 'exploit', 'poc') OR
  mode LIKE '%7%'
);

-- SUID/SGID files changed recently. Replace the mtime window as needed for your incident timeline.
SELECT path, filename, uid, gid, mode, size, mtime, ctime
FROM file
WHERE (mode LIKE '4%' OR mode LIKE '2%')
  AND path NOT LIKE '/proc/%'
  AND path NOT LIKE '/sys/%'
  AND path NOT LIKE '/run/%';
