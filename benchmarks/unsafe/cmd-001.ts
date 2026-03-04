/**
 * UNSAFE: Shell command built with unsanitised variable interpolation.
 * Expected findings: CMD-001
 */
import { execSync } from 'child_process';

export function listDirectory(userDir: string): string {
  // Vulnerable: userDir could be "; rm -rf /" or `$(cat /etc/passwd)`
  return execSync(`ls -la ${userDir}`).toString();
}

export function grepLogs(searchTerm: string): string {
  // Vulnerable: searchTerm is interpolated directly into shell command
  return execSync(`grep -r ${searchTerm} /var/log/app/`).toString();
}
