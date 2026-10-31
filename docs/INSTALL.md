# Installing Lawbat or Redactor (Windows)

This guide covers both installers built from this project:

- **Lawbat** — the full data-room search + review tool (`DataRoomReview-<version>.msi`).
- **Redactor** — the standalone redaction-only tool (`Redactor-<version>.msi`).

You can install one or both — they do not conflict with each other.

No technical knowledge is needed. Follow the numbered steps below.

---

## 1. Why Windows will show a warning

These are **pre-release test builds** and the installer file is **not yet digitally
signed**. Signing costs money and is planned before any public release, but it is not
done yet for this early test build.

Because the file is unsigned, Windows SmartScreen does not recognize the publisher and
will show a warning when you try to run it. **This is expected** — it does not mean the
file is broken or unsafe, but you should still only install a copy you downloaded
yourself from the official GitHub Releases page for this project, and you should verify
its hash (Step 3 below) before running it.

## 2. Getting past the SmartScreen warning

When you double-click the downloaded `.msi` file, you will likely see a blue window
titled **"Windows protected your PC"**. To continue:

1. Click the small text link **"More info"** (it appears under the warning message).
2. A new button labeled **"Run anyway"** will appear. Click it.
3. The normal installer window will open — continue with Step 4 below.

If you instead see a message that says Windows Defender SmartScreen **prevented an
unrecognized app from starting** with no "More info" link, your organization's security
policy may be blocking it entirely — check with whoever manages your computer.

## 3. Verifying the download (recommended, optional)

Every release lists the file's **SHA256 hash** — a fingerprint that proves the file
you downloaded is exactly the one that was built, unmodified. To check it:

1. Open the **Start menu**, type `PowerShell`, and press Enter.
2. In the PowerShell window, type the following, replacing the path with wherever
   the file downloaded (usually your `Downloads` folder), then press Enter:

   ```powershell
   Get-FileHash "$env:USERPROFILE\Downloads\DataRoomReview-0.1.1.msi" -Algorithm SHA256
   ```

   (For the Redactor installer, use `Redactor-0.1.1.msi` instead.)

3. PowerShell prints a long string of letters and numbers under `Hash`. Compare it to
   the SHA256 value published in the release notes for that same file, on the
   [Releases page](../../releases). They should match **exactly** (case does not
   matter). If they don't match, do not run the installer — download it again or ask
   for help.

## 4. Running the installer

1. Follow Step 2 above to get past the SmartScreen warning.
2. Click through the install wizard: **Welcome → License → Choose folder (optional) →
   Install → Finish.**
3. No administrator password is required — this installs just for your own Windows user
   account, not system-wide.
4. When it finishes, a shortcut appears on your Desktop and in the Start menu, named
   **Lawbat** or **Redactor**.

## 5. Where things are installed

You do not need to do anything with this information — it's here in case you (or
whoever supports you) need to find a file.

| | Program files | Your data (documents you index / redact) |
|---|---|---|
| **Lawbat** | `%LOCALAPPDATA%\Programs\DataRoomReview` | `%APPDATA%\DataRoomReview` |
| **Redactor** | `%LOCALAPPDATA%\Programs\Redactor` | `%APPDATA%\Redactor` |

("`%LOCALAPPDATA%`" and "`%APPDATA%`" are folders Windows manages per-user — you can
paste either one directly into the File Explorer address bar to open it.)

Lawbat and Redactor use **separate folders for everything** — installing or removing
one never touches the other, and you can safely have both installed at the same time.

Nothing is ever written back into the folder of documents you point the app at — your
original files are never modified.

## 6. Uninstalling

1. Open **Settings → Apps → Installed apps** (or, on older Windows, **Control Panel →
   Programs and Features**).
2. Find **Lawbat** or **Redactor** in the list, click it, and choose **Uninstall**.
3. This removes the program files and shortcuts. It does **not** delete your data
   folder (Step 5 above) — that's kept in case you want to reinstall later without
   losing anything.
4. To remove your data as well (for example if you want a completely clean machine),
   after uninstalling, open File Explorer, paste `%APPDATA%\DataRoomReview` (or
   `%APPDATA%\Redactor`) into the address bar, and delete that folder manually.

## 7. Upgrading to a newer version

Just run the newer installer the same way (Steps 2–4). It will replace the older
version in place — you don't need to uninstall first, and your data folder is left
untouched.

---

## Getting help

If installation fails, the app fails to start, or a step above doesn't match what you
see, note the exact wording of any error message and where you got stuck, and reach out
through the channel you were given this build from.
