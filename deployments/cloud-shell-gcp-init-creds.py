# Copyright (C) 2026 boostsecurity.io
# SPDX-License-Identifier: AGPL-3.0-or-later

import sqlite3, os, json

cfg = os.environ.get("CLOUDSDK_CONFIG", os.path.expanduser("~/.config/gcloud"))
acct = os.environ.get("SM_GCP_ACCOUNT", "default")
token = os.environ.get("CLOUDSDK_AUTH_ACCESS_TOKEN", "")
if not token:
    exit(0)

for db_name, ddl, vals in [
    ("access_tokens.db",
     "CREATE TABLE IF NOT EXISTS access_tokens "
     "(account_id TEXT PRIMARY KEY, access_token TEXT, token_expiry TIMESTAMP, rapt_token TEXT, id_token TEXT)",
     lambda: (acct, token, "2100-01-01 00:00:00", None, None)),
    ("credentials.db",
     "CREATE TABLE IF NOT EXISTS credentials "
     "(account_id TEXT PRIMARY KEY, value BLOB)",
     lambda: (acct, json.dumps({
         "type": "authorized_user",
         "client_id": "stub",
         "client_secret": "stub",
         "refresh_token": "stub",
     }))),
]:
    c = sqlite3.connect(os.path.join(cfg, db_name))
    c.execute(ddl)
    r = vals()
    c.execute(
        "INSERT OR REPLACE INTO " + db_name.split(".")[0]
        + " VALUES (" + ",".join("?" * len(r)) + ")", r)
    c.commit()
    c.close()
