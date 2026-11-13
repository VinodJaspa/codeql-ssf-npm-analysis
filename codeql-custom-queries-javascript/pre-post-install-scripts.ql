/**
 * @name Pre/Post Install Scripts Detector
 * @description Detects potentially malicious preinstall/postinstall/install scripts in package.json
 * @kind table
 * @id js/pre-post-install-scripts
 * @tags security
 *       external/cwe/cwe-94
 */

import javascript

from
  File f, JsonObject root, JsonObject scriptsObj,
  JsonValue scriptValue, string scriptKey, string scriptStr
where
  // ── Raw file binding (fixes wak-app / nequi-api-utils miss) ─────────────
  f.getBaseName() = "package.json" and
  root.getFile() = f and
  not exists(root.getParent()) and
  scriptsObj = root.getPropValue("scripts") and
  scriptKey in ["preinstall", "postinstall", "install"] and
  scriptValue = scriptsObj.getPropValue(scriptKey) and
  scriptValue instanceof JsonPrimitiveValue and
  scriptStr = scriptValue.(JsonPrimitiveValue).getStringValue() and
  (
    // ── Local script execution ───────────────────────────────────────────
    scriptStr.regexpMatch("^\\./.*") or
    scriptStr.regexpMatch("(?i).*node\\s+.*\\.js.*") or
    scriptStr.regexpMatch("(?i).*(bash|sh)\\s+.*") or

    // ── Network exfiltration ─────────────────────────────────────────────
    scriptStr.regexpMatch("(?i).*(curl|wget|fetch).*") or

    // ── Shell spawning ───────────────────────────────────────────────────
    scriptStr.regexpMatch("(?i).*(sh -c|/bin/sh|/bin/bash).*") or

    // ── Network tools ────────────────────────────────────────────────────
    scriptStr.regexpMatch("(?i).*(nc |nc$|ncat|netcat).*") or
    scriptStr.regexpMatch("(?i).*(nslookup|dig |host ).*") or

    // ── Reconnaissance ───────────────────────────────────────────────────
    scriptStr.regexpMatch("(?i).*(whoami|hostname|uname|ifconfig|ipconfig).*") or
    scriptStr.regexpMatch("(?i).*(env |printenv).*") or       // deduplicated

    // ── Credential access ────────────────────────────────────────────────
    scriptStr.regexpMatch("(?i).*(cat /etc/passwd|cat /etc/shadow).*") or
    scriptStr.regexpMatch("(?i).*(find ~/\\.ssh|find ~/.ssh).*") or
    scriptStr.regexpMatch("(?i).*xargs cat.*") or

    // ── User manipulation ────────────────────────────────────────────────
    scriptStr.regexpMatch("(?i).*(useradd|adduser|passwd|openssl passwd).*") or

    // ── Encoding into exfil ──────────────────────────────────────────────
    scriptStr.regexpMatch("(?i).*(base64|xxd|od ).*") or

    // ── Direct script execution ──────────────────────────────────────────
    scriptStr.regexpMatch("(?i).*\\./.*\\.sh.*") or
    scriptStr.regexpMatch("(?i).*node install\\.js.*") or
    scriptStr.regexpMatch("^index\\.js$") or
    scriptStr.regexpMatch("^\\./index\\.js$") or

    // ── Python/perl/ruby execution ───────────────────────────────────────
    scriptStr.regexpMatch("(?i).*(python -c|python3 -c|perl -e|ruby -e).*") or

    // ── Package managers fetching remote ─────────────────────────────────
    scriptStr.regexpMatch("(?i).*(pip install|npm install --).*") or

    // ── Reverse shell patterns ───────────────────────────────────────────
    scriptStr.regexpMatch("(?i).*(/dev/tcp/|/dev/udp/).*") or  // deduplicated
    scriptStr.regexpMatch("(?i).*(>& /dev/|0>&1).*") or
    scriptStr.regexpMatch("(?i).*(-e /bin/bash|-e /bin/sh).*") or

    // ── OOB DNS Exfiltration (behavioral — not domain specific) ──────────
    scriptStr.regexpMatch("(?i).*(dig|nslookup|host)\\s+.*\\$\\([^)]+\\)\\..*") or
    scriptStr.regexpMatch("(?i).*(dig|nslookup|host)\\s+.*`[^`]+`\\..*") or
    scriptStr.regexpMatch("(?i).*(xxd|base64).*\\|.*(dig|nslookup|host).*") or

    // ── HTTP Callback Exfiltration (behavioral — not domain specific) ─────
    scriptStr.regexpMatch("(?i).*(curl|wget).*-[Ff]\\s*\\w+=\\$\\([^)]+\\).*") or
    scriptStr.regexpMatch("(?i).*(curl|wget).*\\?\\w+=\\$\\([^)]+\\).*") or
    scriptStr.regexpMatch("(?i).*(curl|wget)\\s+https?://[^\\s]*/\\$\\([^)]+\\).*") or
    scriptStr.regexpMatch("(?i).*(curl|wget).*(--data|-d).*\\$\\([^)]+\\).*") or

    // ── Raw IP addresses ─────────────────────────────────────────────────
    scriptStr.regexpMatch(".*\\d{1,3}(\\.\\d{1,3}){3}.*") or   // deduplicated

    // ── SSH key access ───────────────────────────────────────────────────
    scriptStr.regexpMatch("(?i).*\\.ssh/id_rsa.*") or
    scriptStr.regexpMatch("(?i).*\\.ssh/authorized_keys.*") or

    // ── System recon ─────────────────────────────────────────────────────
    scriptStr.regexpMatch("(?i).*(cat /etc/hostname|/etc/os-release).*") or

    // ── Windows background execution ─────────────────────────────────────
    scriptStr.regexpMatch("(?i).*start /B.*") or               // deduplicated

    // ── SSH harvesting ───────────────────────────────────────────────────
    scriptStr.regexpMatch("(?i).*find .*\\.ssh.*") or

    // ── Command substitution exfil ───────────────────────────────────────
    scriptStr.regexpMatch("(?i).*\\$\\(.*\\).*")
  )
select f.getRelativePath() as filePath,
  root.getLocation().getStartLine() as startLine,
  root.getLocation().getEndLine() as endLine,
  "Potentially malicious install script in " + scriptKey + ": \"" + scriptStr + "\"." as message