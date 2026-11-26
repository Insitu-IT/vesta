# Manage installation licenses

Select a visible licensing reminder or open **Settings → License**. Installation administrators can see and copy the installation ID and current license ID, and check the license class, coverage and expiry. In a multi-organization installation, a platform administrator manages the license.

## Replace the license

1. Copy the installation ID and sign in to the [Vesta licensing portal](https://vestabackup.com/portal/licensing) on a connected device. Select the installed release. Request or renew a license for the same installation ID.
2. Download the complete signed JSON file. For a disconnected site, transfer it through your normal offline delivery process.
3. On the installation's **License** screen choose the file and select **Import file**, or paste the signed JSON and select **Import pasted license**.
4. Check the success message, license ID and expiry. If verification fails, the screen shows the reason and the previously accepted license. Check the installation ID, trusted issuer, validity dates and that you supplied the complete document.

A Vesta Community 6.1.0 free license covers two UTC calendar years. Renew within the last 30 days to add two years to the current expiry. A renewal after expiry starts at issuance. A 29 February anniversary falls on 28 February in a year without a leap day. Backup and recovery continue during renewal.

## Verify a license locally

The installation kit supplies the issuer's public verification keys. If you manage verification keys yourself, compare the key ID and fingerprint with your independently approved copy before installing a new public key. Keep previous public keys while they are needed by outstanding licenses and rollback procedures.

## Acknowledge a reminder

An installation administrator can acknowledge a licensing reminder in the console after reviewing it. Acknowledgement records that the administrator has seen the reminder. Use the [licensing portal](https://vestabackup.com/portal/licensing) to obtain or renew the license.
