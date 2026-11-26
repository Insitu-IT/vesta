# Register or renew a Vesta installation

Open **Settings → License**, or select a visible licensing reminder in the console. An installation administrator can see the installation ID, the current license ID, coverage and expiry on this screen. [Check which license applies](ELIGIBILITY.md).

## Register for a free license

1. Copy the installation ID. Open the [licensing portal](https://account.vestabackup.com/portal/licensing) on a connected device and sign in with your email.
2. Choose free registration, select your installed release and describe how you use Vesta. Review the terms, eligibility schedule and privacy notice. The portal tells you whether this installation needs a license.
3. If the portal issues a free license, download the signed JSON. For an air-gapped installation, transfer it through your approved offline process.
4. On the installation's **License** screen, select the file and choose **Import file**, or paste the complete signed JSON and choose **Import pasted license**. Check the displayed license ID and expiry after import. Verification runs locally and a failed import preserves the previous license.

## Renew a free license

The 6.1.0 free license covers one installation for two UTC calendar years. Use the same portal account and installation ID. Renewal opens 30 days before expiry and adds two years to the existing expiry. After expiry, the new term starts at issuance. A 29 February anniversary falls on 28 February in a year without a leap day.

Download and import the replacement on the same installation. Backups, schedules and restores keep running throughout renewal. The [installation licensing guide](packaging/okd/runbooks/licensing.md) covers local trust and import errors.

## Ask about commercial licensing

Choose **Request commercial licensing** in the [licensing portal](https://account.vestabackup.com/portal/licensing). The licensing team reviews your inquiry and follows up by email.
