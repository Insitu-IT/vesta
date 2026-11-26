# Read backup status with the operator API

Open `/docs` or `/redoc` at the HTTPS address of your Vesta API to browse operations. Download `/openapi.json` from the same address for the schema that matches your installed configuration. These pages work offline. The [API reference on the Vesta website](https://vestabackup.com/docs/api/) also lets you choose a release and the Community or Community with mTLS profile.

## List your backups

Set `VESTA_API` to your API's HTTPS origin. Set `VESTA_CURL_CONFIG` to a private curl configuration containing your authorized operator's authentication header and the site's trusted CA when required.

```sh
curl --fail-with-body --silent --show-error --config "$VESTA_CURL_CONFIG" \
  "$VESTA_API/api/v1/backups"
```

Look up an individual point with `GET /api/v1/backups/{backup_id}`. Use the credentials and organization that own that backup.

## Check an interrupted request

When a request returns a request ID, keep that UUID. If the response was interrupted, read the same request with the original actor and organization:

```sh
curl --fail-with-body --silent --show-error --config "$VESTA_CURL_CONFIG" \
  "$VESTA_API/api/v1/operator/requests/$REQUEST_ID"
```

Check the returned state and the operation’s documented recovery steps before resuming. An accepted request can still be running. To verify a backup end to end, [restore a known file](first-recovery.md).
