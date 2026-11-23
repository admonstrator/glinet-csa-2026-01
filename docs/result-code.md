# The Result in Plain Words

Part of the [gl-helper triage script](../README.md).

The output is written for people who know these devices. For everyone else the script
prints an address directly under the verdict:

```
   Verdict: ATTACKED - a command sent through GoodCloud ran on this device

    >>> This result in plain words, with what to do (English, German, Chinese):
   >>> https://csa.gl-i.net/#AA006011D
```

On a terminal the first of these lines is a green bar and the address is underlined, so
that it is the first thing a reader sees. The bar uses reverse video, so its text has the
terminal's own background color and stays readable in dark and light themes.

The page behind it explains what was found, what that means and what to do, in English,
German and Chinese. Over ssh the address often cannot be clicked, so it is short enough to
type: nine characters, in upper or lower case. They hold the script's version, router or KVM, the
kinds of findings, whether GoodCloud is on, whether the device was restarted since the
attacks began, what `--fix` did and whether other changes are listed for review. The ninth
character is a check, so a mistyped code is refused instead of explaining another result.

Where the script knows the model and its firmware version, five more characters follow
after a dash (`csa.gl-i.net/#AA006011D-2PJ2W`, since 2.45). With them the page says whether
newer firmware exists for the device, from the list of
[firmware.gl-i.net](https://firmware.gl-i.net/). The first nine work without them.

No path, no name, no serial number, no ID: nothing in the code tells this device from
another of its kind. It comes after `#`, the part of an address that a browser does not
send: opening it sends nothing about the device, and it can be posted in a forum as it is.
The page does not check anything; it explains the code it is given. With `--fix` the
address is printed under the verdict after the cleanup, and then also says what the
cleanup did.

Since 2.39; under the verdict since 2.40; nine characters since 2.41; model and firmware
since 2.45. The longer addresses
of 2.39 and 2.40 still work.
