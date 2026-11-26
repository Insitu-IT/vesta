# Register or renew a Vesta installation

Open **Settings → License**, or select a visible licensing reminder in the console. An installation administrator can see the installation ID, the current license ID, coverage and expiry on this screen. [Check which license applies](ELIGIBILITY.md).

## Get a license

1. Copy the installation ID. Open the [licensing portal](https://vestabackup.com/portal/licensing) on a connected device.
2. Select the installed release, confirm your contact and end use, and review its terms, Eligibility Schedule and privacy notice. Choose free registration or request a paid license.
3. Download the signed JSON. For an air-gapped installation, transfer it through your approved offline process.
4. On the installation's **License** screen, select the file and choose **Import file**, or paste the complete signed JSON and choose **Import pasted license**. Check the displayed license ID and expiry after import. Verification runs locally and a failed import preserves the previous license.

## Renew a free license

The 6.1.0 free license covers one installation for two UTC calendar years. Use the same portal account and installation ID. Renewal opens 30 days before expiry and adds two years to the existing expiry. After expiry, the new term starts at issuance. A 29 February anniversary falls on 28 February in a year without a leap day.

Download and import the replacement on the same installation. Backups, schedules and restores keep running throughout renewal. The [installation licensing guide](packaging/okd/runbooks/licensing.md) covers local trust and import errors.
