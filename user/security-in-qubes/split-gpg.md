---
layout: doc
title: Split GPG
permalink: /doc/split-gpg/
redirect_from:
- /de/doc/split-gpg/
- /de/doc/SplitGpg/
- /de/doc/UserDoc/SplitGpg/
- /de/wiki/UserDoc/SplitGpg/
- /de/doc/open-pgp/
- /de/doc/open-pgp/
- /de/doc/OpenPGP/
- /de/doc/UserDoc/OpenPGP/
- /de/wiki/UserDoc/OpenPGP/
---

# Qubes Split GPG #

Split GPG (also aufgeteiltes GPG) implementiert ein Konzept vergleichbar mit Smart Cards auf denen der private GPG Schlüssel liegt, nur mit dem Unterschied, das die Rolle der "Smart Card" von einer anderen Qubes AppVM übernommen wird.  
Auf diesen Weg kann eine nicht so wirklich vertrauenswürdige AppVM, zum Beispiel die mit dem E-Mail programm, alle Ver- und Entschlüsselungsaufgaben an eine vertrauenswürdigere, vom Internet getrennte AppVM weiterleiten.  
Dies Verhindert, das eine Kompromitierung der E-Mail VM (leider kein so abwegiges Szenario) , oder einer anderen, es den Angreifenden ermöglicht die privaten GPG Schlüssel zu stehlen.  

[![split-gpg-diagram.png](/attachment/wiki/SplitGpg/split-gpg-diagram.png)](/attachment/wiki/SplitGpg/split-gpg-diagram.png)

Dieses Diagramm liefet einen Überblick über die Architektur von Split GPG.

## Vorteile von Split GPG gegenüber der traditionellen GPG Smart Card ##

Wir denken oft, dass das Benutzen einer Smart Card ultimative Sicherheit für unsere GPG Keys liefert.
Dies stimmt zwar (solange die Angreifenden keinen, normalerweise sehr teuren, Weg finden die Schlüssel von der Smart Card zu extrahieren) betrifft aber nur den privaten Schlüssel selbst.
Jedoch gibt es nichts was die Angreifenden davon abhält die Smart Card dabit zu beauftragen ein Document für die Angreifenden und nicht für den Nutzenden zu entschlüsseln.
Mit anderen Worten, den privaten Schlüssel des Nutzenden zu schützen ist wichtig, es geht aber eigentlich darum, dir Daten des Nutzenden zu schützen, was die Smart Card nicht kann, da sie nicht weiß welcher Auftrag von dem Nutzenden kommt, und welcher von den Angreifenden.
(Genauso macht die Smart Card das Signieren eines Documentes auch nicht sicherer, da der Nutzer nicht wissen kann was wirklich Signiert wird. Leider ist dies ein Problem das momentan noch nicht von Split GPG gelöst wird.)

Mit Split GPG ist dieses Problem jedoch erheblich verkleinert, denn der Nutzende muss den Zugriff auf den Schlüssel freigeben (Standartmäßig für 5 minuten) und wird über eine Benachrichtigung über jeden Schlüsselzugriff informiert.
So ist es relativ leicht einen unerwartetenZ Zugriff auf den Schlüssel zu erkennen.

[![r2-split-gpg-1.png](/attachment/wiki/SplitGpg/r2-split-gpg-1.png)](/attachment/wiki/SplitGpg/r2-split-gpg-1.png)
[![r2-split-gpg-3.png](/attachment/wiki/SplitGpg/r2-split-gpg-3.png)](/attachment/wiki/SplitGpg/r2-split-gpg-3.png)

## Split GPG einrichten ##

Stellen sie sicher, dass das Packet `qubes-gpg-split-dom0` in dom0 installiert ist.

    [user@dom0 ~]$ sudo qubes-dom0-update qubes-gpg-split-dom0
    
Stellen sie sicher, dass das Packet `qubes-gpg-split` in den TemplateVMs auf denen die AppVMs basieren in denen sie Split GPG nutzen wollen

Für Debian oder Whonix:

    [user@debian-10 ~]$ sudo apt install qubes-gpg-split

Für Fedora:

    [user@fedora-32 ~]$ sudo dnf install qubes-gpg-split

### Einrichten der Split GPG backend VM###

Erstellen sie als erstes eine AppVM die nur dazu dienen soll ihren privaten GPG Schlüssel sicher aufubewaren.
Wir empfehlen diese AppVM vom Internet vernzuhalten. Stellen sie dazu `none` in den Einstellungen der AppVM bei netvm ein.
Im nachfolgenden Beispiel heist die AppVM, die die privaten Schlüssel hält `work-gpg`

Stellen sie sicher das `work-gpg` das Programm `gpg` installiert hat
Fügen sie nun die privaten Schlüssel in den Schlüsselbund in `work-gpg` ein. Sie können dies später auch wiederholen.

    [user@work-gpg ~]$gpg --import %Datei mit ihren Privaten Schlüssel%

Um zu überprüfen welche privaten Schlüssel in ihrem GPG Schlüsselbung sind, nutzen sie bitte:

    [user@work-gpg ~]$ gpg -K
    /home/user/.gnupg/secring.gpg
    -----------------------------
    sec   4096R/3F48CB21 2012-11-15
    uid                  Qubes OS Security Team <security@qubes-os.org>
    ssb   4096R/30498E2A 2012-11-15
    (...)

Dies war im grunde alles was sie machen müssen.
Sie können aber noch den Standart Zeit, wie lange die erlaubnis auf den Schlüsselbund zuzugreifen gültig ist, verändern.
Führen sie dazu folgenden Befehl aus:

    [user@work-gpg ~]$ echo "export QUBES_GPG_AUTOACCEPT=%Zeit in sekunden%" >> ~/.profile


Früher war diese Einstellung in ~/.bash_profile. dies Funktioniert nun nicht mehr. Sollten sie noch die alte Einstellung verändern *müssen* sie dies nun umstellen.

Bitte beachten sie die Probleme mit Passwortgeschützten Schlüsseln im [Aktuelle Einschränkungen][aktuelle-einschränkungen] Absatz.

### Konfigurieren sie die normalen AppVMs Split GPG zu nutzen ###

Normalerweise sollte es ausreichen die Variable `QUBES_GPG_DOMAIN` auf die VM zu setzen, die die Schlüssel verwaltet, und `qubes-gpg-client` anstelle von `gpg` zu nutzen, z.B.:

    [user@work-email ~]$ export QUBES_GPG_DOMAIN=work-gpg
    [user@work-email ~]$ gpg -K
    [user@work-email ~]$ qubes-gpg-client -K
    /home/user/.gnupg/secring.gpg
    -----------------------------
    sec   4096R/3F48CB21 2012-11-15
    uid                  Qubes OS Security Team <security@qubes-os.org>
    ssb   4096R/30498E2A 2012-11-15
    (...)

    [user@work-email ~]$ qubes-gpg-client secret_message.txt.asc
    (...)

Beachten sie bitte, dass `gpg -K` (wie sie es normal verwenden würden) keine privaten Schlüssel in der AppVM anzeigt.

Ein Hinweis zu `gpg` und `gpg2`:

In dieser Anleitung wird zwar von `gpg` gesprochen, Split GPG nutzt jedoch `gpg2`. Sollten sie Probleme mit ihrer Einstellung haben beachten sie dies bitte.

### Advanced Configuration ###

The `qubes-gpg-client-wrapper` script sets the `QUBES_GPG_DOMAIN` variable automatically based on the content of the file `/rw/config/gpg-split-domain`, which should be set to the name of the GPG backend VM. This file survives the AppVM reboot, of course.

    [user@work-email ~]$ sudo bash
    [root@work-email ~]$ echo "work-gpg" > /rw/config/gpg-split-domain

Split GPG's default qrexec policy requires the user to enter the name of the AppVM containing GPG keys on each invocation. To improve usability for applications like Thunderbird with Enigmail, in `dom0` place the following line at the top of the file `/etc/qubes-rpc/policy/qubes.Gpg`:

    work-email  work-gpg  allow

where `work-email` is the Thunderbird + Enigmail AppVM and `work-gpg` contains your GPG keys.

You may also edit the qrexec policy file for Split GPG in order to tell Qubes your default gpg vm (qrexec prompts will appear with the gpg vm preselected as the target, instead of the user needing to type a name in manually). To do this, append `,default_target=<vmname>` to `ask` in `/etc/qubes-rpc/policy/qubes.Gpg`. For the examples given on this page:

    @anyvm  @anyvm  ask,default_target=work-gpg

Note that, because this makes it easier to accept Split GPG's qrexec authorization prompts, it may decrease security if the user is not careful in reviewing presented prompts. This may also be inadvisable if there are multiple AppVMs with Split GPG set up.

## Using Thunderbird ##

### Thunderbird 78 and higher

Starting with version 78, Thunderbird has a built-in PGP feature and no longer requires the Enigmail extension. For users coming from the Enigmail extension, the built-in functionality is more limited currently, including that **public keys must live in your `work-email` qube with Thunderbird rather than your offline `work-gpg` qube**.

In `work-email`, use the Thunderbird config editor (found at the bottom of preferences/options), and search for `mail.openpgp.allow_external_gnupg`. Switch the value to true. Still in config editor, search for `mail.openpgp.alternative_gpg_path`. Set its value to `/usr/bin/qubes-gpg-client-wrapper`. Restart Thunderbird after this change.

[![tb78-1.png](/attachment/wiki/SplitGpg/tb78-1.png)](/attachment/wiki/SplitGpg/tb78-1.png)
[![tb78-2.png](/attachment/wiki/SplitGpg/tb78-2.png)](/attachment/wiki/SplitGpg/tb78-2.png)
[![tb78-3.png](/attachment/wiki/SplitGpg/tb78-3.png)](/attachment/wiki/SplitGpg/tb78-3.png)

You need to obtain your key ID which should be **exactly 16 characters**. Enter the command `qubes-gpg-client-wrapper -K --keyid-format long`:

```
[user@work-email ~]$ qubes-gpg-client-wrapper -K --keyid-format long
/home/user/.gnupg/pubring.kbx
-----------------------------
sec   rsa2048/777402E6D301615C 2020-09-05 [SC] [expires: 2022-09-05]
      F7D2D4E922DFB7B2589AF3E9777402E6D301615C
uid                 [ultimate] Qubes test <user@localhost>
ssb   rsa2048/370CE932085BA13B 2020-09-05 [E] [expires: 2022-09-05]
```

```
[user@work-email ~]$ qubes-gpg-client-wrapper --armor --export 777402E6D301615C > 777402E6D301615C.asc
```

Open the Account Settings and open the *End-to-End Encryption* tab of the respective email account. Click the *Add Key* button. You'll be offered the choice *Use your external key through GnuPG*. Select it and click Continue.

[![tb78-4.png](/attachment/wiki/SplitGpg/tb78-4.png)](/attachment/wiki/SplitGpg/tb78-4.png)
[![tb78-5.png](/attachment/wiki/SplitGpg/tb78-5.png)](/attachment/wiki/SplitGpg/tb78-5.png)

The key ID reference you would need here is `777402E6D301615C`. Now paste or type the ID of the secret key that you would like to use. Be careful to enter it correctly, because your input isn't verified. Confirm to save this key ID. Now you can select the key ID to use.

[![tb78-6.png](/attachment/wiki/SplitGpg/tb78-6.png)](/attachment/wiki/SplitGpg/tb78-6.png)
[![tb78-7.png](/attachment/wiki/SplitGpg/tb78-7.png)](/attachment/wiki/SplitGpg/tb78-7.png)

This key ID will be used to digitally sign or send an encrypted message with your account. For this to work, Thunderbird needs a copy of your public key. At this time, Thunderbird doesn't fetch the public key from `/usr/bin/qubes-gpg-client-wrapper`, you must manually import it. Export the key as follow (assuming the key ID would be `777402E6D301615C`):

[![tb78-8.png](/attachment/wiki/SplitGpg/tb78-8.png)](/attachment/wiki/SplitGpg/tb78-8.png)
[![tb78-9.png](/attachment/wiki/SplitGpg/tb78-9.png)](/attachment/wiki/SplitGpg/tb78-9.png)

Use Thunderbird's Tools menu to open *OpenPGP Key Management*. In that window, use the File menu to access the *Import Public Key(s) From File* command. Open the file with your public key. After the import was successful, right click on the imported key in the list and select *Key Properties*. You must mark your own key as *Yes, I've verified in person this key has the correct fingerprint*.

Once this is done, you should be able to send an encrypted and signed email by selecting *Require Encryption* or *Digitally Sign This Message* in the compose menu *Options* or *Security* toolbar button. You can try it by sending an email to yourself.

[![tb78-10.png](/attachment/wiki/SplitGpg/tb78-10.png)](/attachment/wiki/SplitGpg/tb78-10.png)

For more details about using smart cards/Split GPG with Thunderbird PGP feature, please see [Thunderbird:OpenPGP:Smartcards] from which the above documentation is inspired.

### Older Thunderbird versions

For Thunderbird versions below 78, the traditional Enigmail + Split GPG setup is required.
It is recommended to set up and use `/usr/bin/qubes-gpg-client-wrapper`, as discussed above, in Thunderbird through the Enigmail addon.

**Warning:** Before adding any account, configuring Enigmail with `/usr/bin/qubes-gpg-client-wrapper` is **required**. By default, Enigmail will generate a default GPG key in `work-email` associated with the newly created Thunderbird account. Generally, it corresponds to the email used in `work-gpg` associated to your private key. In consequence, a new, separate private key will be stored in `work-email` but it _does not_ correspond to your private key in `work-gpg`. Comparing the `fingerprint` or `expiration date` will show that they are not the same private key. In order to prevent Enigmail using this default generated local key in `work-email`, you can safely remove it.

On a fresh Enigmail install, your need to change the default `Enigmail Junior Mode`. Go to Thunderbird preferences and then privacy tab. Select `Force using S/MIME and Enigmail`. Then, in the preferences of Enigmail, make it point to `/usr/bin/qubes-gpg-client-wrapper` instead of the standard GnuPG binary:

[![tb-enigmail-split-gpg-settings-2.png](/attachment/wiki/SplitGpg/tb-enigmail-split-gpg-settings-2.png)](/attachment/wiki/SplitGpg/tb-enigmail-split-gpg-settings-2.png)

## Using Keybase with Split GPG ##

Keybase, a security focused messaging and file-sharing app with GPG integration, can be configured to use Split GPG.

The Keybase service does not preserve/pass the `QUBES_GPG_DOMAIN` environment variable through to underlying GPG processes, so it **must** be configured to use `/usr/bin/qubes-gpg-client-wrapper` (as discussed above) rather than `/usr/bin/qubes-gpg-client`.

The following command will configure Keybase to use `/usr/bin/qubes-gpg-client-wrapper` instead of its built-in GPG client:

```
$ keybase config set gpg.command /usr/bin/qubes-gpg-client-wrapper
```

Now that Keybase is configured to use `qubes-gpg-client-wrapper`, you will be able to use `keybase pgp select` to choose a GPG key from your backend GPG AppVM and link that key to your Keybase identity.

## Using Git with Split GPG ##

Git can be configured to used with Split GPG, something useful if you would like to contribute to the Qubes OS Project as every commit is required to be signed.
The most basic `~/.gitconfig` file to with working Split GPG looks something like this.

    [user]
    name = YOUR NAME
    email = YOUR EMAIL ADDRESS
    signingkey = YOUR KEY ID

    [gpg]
    program = qubes-gpg-client-wrapper

Your key id is the public id of your signing key, which can be found by running `qubes-gpg-client -k`.
In this instance, the key id is DD160C74.

    [user@work-email ~]$ qubes-gpg-client -k
    /home/user/.gnupg/pubring.kbx
    -----------------------------
    pub   rsa4096/DD160C74 2016-04-26
    uid                    Qubes User

To sign commits, you now add the "-S" flag to your commit command, which should prompt for Split GPG usage.
If you would like automatically sign all commits, you can add the following snippet to `~/.gitconfig`.

    [commit]
    gpgsign = true

Lastly, if you would like to add aliases to sign and verify tags using the conventions the Qubes OS Project recommends, you can add the following snippet to `~/.gitconfig`.

    [alias]
    stag = "!id=`git rev-parse --verify HEAD`; git tag -s user_${id:0:8} -m \"Tag for commit $id\""
    vtag = !git tag -v `git describe`

Replace `user` with your short, unique nickname.
Now you can use `git stag` to add a signed tag to a commit and `git vtag` to verify the most recent tag that is reachable from a commit.

## Importing public keys ###

Use `qubes-gpg-import-key` in the client AppVM to import the key into the GPG backend VM.

    [user@work-email ~]$ export QUBES_GPG_DOMAIN=work-gpg
    [user@work-email ~]$ qubes-gpg-import-key ~/Downloads/marmarek.asc

A safe, unspoofable user consent dialog box is displayed.

[![r2-split-gpg-5.png](/attachment/wiki/SplitGpg/r2-split-gpg-5.png)](/attachment/wiki/SplitGpg/r2-split-gpg-5.png)

Selecting "Yes to All" will add a line in the corresponding [RPC Policy] file.

## Advanced: Using Split GPG with Subkeys ##

Users with particularly high security requirements may wish to use Split GPG with [​subkeys].
However, this setup comes at a significant cost: It will be impossible to sign other people's keys with the master secret key without breaking this security model.
Nonetheless, if signing others' keys is not required, then Split GPG with subkeys offers unparalleled security for one's master secret key.

### Setup Description ###

In this example, the following keys are stored in the following locations (see below for definitions of these terms):

| PGP Key(s) | VM Name      |
| ---------- | ------------ |
| `sec`      | `vault`      |
| `ssb`      | `work-gpg`   |
| `pub`      | `work-email` |

 * `sec` (master secret key)

   Depending on your needs, you may wish to create this as a **certify-only (C)** key, i.e., a key which is capable only of signing (a.k.a., "certifying") other keys.
   This key may be created *without* an expiration date.
   This is for two reasons.
   First, the master secret key is never to leave the `vault` VM, so it is extremely unlikely ever to be obtained by an adversary (see below).
   Second, an adversary who *does* manage to obtain the master secret key either possesses the passphrase to unlock the key (if one is used) or does not.
   An adversary who *does* possess the passphrase can simply use it to legally extend the expiration date of the key (or remove it entirely).
   An adversary who does *not* possess the passphrase cannot use the key at all.
   In either case, an expiration date provides no additional benefit.

   By the same token, however, having a passphrase on the key is of little value.
   An adversary who is capable of stealing the key from your `vault` would almost certainly also be capable of stealing the passphrase as you enter it.
   An adversary who obtains the passphrase can then use it in order to change or remove the passphrase from the key.
   Therefore, using a passphrase at all should be considered optional.
   It is, however, recommended that a **revocation certificate** be created and safely stored in multiple locations so that the master keypair can be revoked in the (exceedingly unlikely) event that it is ever compromised.

 * `ssb` (secret subkey)

   Depending on your needs, you may wish to create two different subkeys: one for **signing (S)** and one for **encryption (E)**.
   You may also wish to give these subkeys reasonable expiration dates (e.g., one year).
   Once these keys expire, it is up to you whether to *renew* these keys by extending the expiration dates or to create *new* subkeys when the existing set expires.

   On the one hand, an adversary who obtains any existing encryption subkey (for example) will be able to use it in order to decrypt all emails (for example) which were encrypted to that subkey.
   If the same subkey were to continue to be used--and its expiration date continually extended--only that one key would need to be stolen (e.g., as a result of the `work-gpg` VM being compromised; see below) in order to decrypt *all* of the user's emails.
   If, on the other hand, each encryption subkey is used for at most approximately one year, then an adversary who obtains the secret subkey will be capable of decrypting at most approximately one year's worth of emails.

   On the other hand, creating a new signing subkey each year without renewing (i.e., extending the expiration dates of) existing signing subkeys would mean that all of your old signatures would eventually read as "EXPIRED" whenever someone attempts to verify them.
   This can be problematic, since there is no consensus on how expired signatures should be handled.
   Generally, digital signatures are intended to last forever, so this is a strong reason against regularly retiring one's signing subkeys.

 * `pub` (public key)

   This is the complement of the master secret key.
   It can be uploaded to keyservers (or otherwise publicly distributed) and may be signed by others.

 * `vault`

   This is a network-isolated VM.
   The initial master keypair and subkeys are generated in this VM.
   The master secret key *never* leaves this VM under *any* circumstances.
   No files or text is *ever* [copied] or [pasted] into this VM under *any* circumstances.

 * `work-gpg`

   This is a network-isolated VM.
   This VM is used *only* as the GPG backend for `work-email`.
   The secret subkeys (but *not* the master secret key) are [copied] from the `vault` VM to this VM.
   Files from less trusted VMs are *never* [copied] into this VM under *any* circumstances.

 * `work-email`

   This VM has access to the mail server.
   It accesses the `work-gpg` VM via the Split GPG protocol.
   The public key may be stored in this VM so that it can be attached to emails and for other such purposes.

### Security Benefits ###

In the standard Split GPG setup, there are at least two ways in which the `work-gpg` VM might be compromised.
First, an attacker who is capable of exploiting a hypothetical bug in `work-email`'s [​MUA] could gain control of the `work-email` VM and send a malformed request which exploits a hypothetical bug in the GPG backend (running in the `work-gpg` VM), giving the attacker control of the `work-gpg` VM.
Second, a malicious public key file which is imported into the `work-gpg` VM might exploit a hypothetical bug in the GPG backend which is running there, again giving the attacker control of the `work-gpg` VM.
In either case, such an attacker might then be able to leak both the master secret key and its passphrase (if any is used, it would regularly be input in the work-gpg VM and therefore easily obtained by an attacker who controls this VM) back to the `work-email` VM or to another VM (e.g., the `netvm`, which is always untrusted by default) via the Split GPG protocol or other [covert channels].
Once the master secret key is in the `work-email` VM, the attacker could simply email it to himself (or to the world).

In the alternative setup described in this section (i.e., the subkey setup), even an attacker who manages to gain access to the `work-gpg` VM will not be able to obtain the user's master secret key since it is simply not there.
Rather, the master secret key remains in the `vault` VM, which is extremely unlikely to be compromised, since nothing is ever copied or transferred into it.
<sup>\*</sup> The attacker might nonetheless be able to leak the secret subkeys from the `work-gpg` VM in the manner described above, but even if this is successful, the secure master secret key can simply be used to revoke the compromised subkeys and to issue new subkeys in their place.
(This is significantly less devastating than having to create a new *master* keypair.)

<sup>\*</sup>In order to gain access to the `vault` VM, the attacker would require the use of, e.g., a general Xen VM escape exploit or a [signed, compromised package which is already installed in the TemplateVM][trusting-templates] upon which the `vault` VM is based.

### Subkey Tutorials and Discussions ###

(Note: Although the tutorials below were not written with Qubes Split GPG in mind, they can be adapted with a few commonsense adjustments.
As always, exercise caution and use your good judgment.)

-   [​"OpenPGP in Qubes OS" on the qubes-users mailing list][openpgp-in-qubes-os]
-   [​"Creating the Perfect GPG Keypair" by Alex Cabal][cabal]
-   [​"GPG Offline Master Key w/ smartcard" maintained by Abel Luck][luck]
-   [​"Using GnuPG with QubesOS" by Alex][apapadop]

## Current limitations ##

- Current implementation requires importing of public keys to the vault domain.
  This opens up an avenue to attack the gpg running in the backend domain via a hypothetical bug in public key importing code.
  See ticket [#474] for more details and plans how to get around this problem, as well as the section on [using Split GPG with subkeys].

- It doesn't solve the problem of allowing the user to know what is to be signed before the operation gets approved.
  Perhaps the GPG backend domain could start a DisposableVM and have the to-be-signed document displayed there? To Be Determined.

- The Split GPG client will fail to sign or encrypt if the private key in the GnuPG backend is protected by a passphrase.
  It will give an `Inappropriate ioctl for device` error.
  Do not set passphrases for the private keys in the GPG backend domain.
  Doing so won't provide any extra security anyway, as explained in the introduction and in [using Split GPG with subkeys].
  If you are generating a new key pair, or if you have a private key that already has a passphrase, you can use `gpg2 --edit-key <key_id>` then `passwd` to set an empty passphrase.
  Note that `pinentry` might show an error when you try to set an empty passphrase, but it will still make the change.
  (See [this StackExchange answer][se-pinentry] for more information.) 
  Note: The error shows only if you **do not** have graphical pinentry installed. 


[#474]: https://github.com/QubesOS/qubes-issues/issues/474
[using Split GPG with subkeys]: #advanced-using-split-gpg-with-subkeys
[intro]: #what-is-split-gpg-and-why-should-i-use-it-instead-of-the-standard-gpg
[se-pinentry]: https://unix.stackexchange.com/a/379373
[​subkeys]: https://wiki.debian.org/Subkeys
[copied]: /doc/copying-files#security
[pasted]: /doc/copy-paste#security
[​MUA]: https://en.wikipedia.org/wiki/Mail_user_agent
[covert channels]: /doc/data-leaks
[trusting-templates]: /doc/templates/#trusting-your-templatevms
[openpgp-in-qubes-os]: https://groups.google.com/d/topic/qubes-users/Kwfuern-R2U/discussion
[cabal]: https://alexcabal.com/creating-the-perfect-gpg-keypair/
[luck]: https://gist.github.com/abeluck/3383449
[apapadop]: https://apapadop.wordpress.com/2013/08/21/using-gnupg-with-qubesos/
[current-limitations]: #current-limitations
[RPC Policy]: /doc/rpc-policy/
[Thunderbird:OpenPGP:Smartcards]: https://wiki.mozilla.org/Thunderbird:OpenPGP:Smartcards

