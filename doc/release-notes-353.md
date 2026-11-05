PSBT signing ignores Sign while signing is in progress
======================================================

In the PSBT operations dialog, Sign now does nothing while a signing attempt
is in progress, from the passphrase prompt until signing finishes, so one
Sign makes at most one signing attempt. Mouse and keyboard input cannot reach
the dialog behind the passphrase prompt, but an accessibility client, such as
VoiceOver, or a UI automation tool still can. In v1.0.0, pressing Sign through
one while the prompt was open started a second signing attempt, with a second
passphrase prompt. Copy and Save are unavailable for the whole attempt,
including the prompt.

qbit-qt also no longer uses freed memory when the dialog is closed while its
passphrase prompt is open. Closing it this way, again only possible through
an accessibility client or automation tool, now ends the signing attempt
before it signs and leaves the wallet locked.
