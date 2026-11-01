"""allclear — account-wide GitHub exposure audit with calibrated findings.

The thesis of this package, in one paragraph:

Secret scanners are good at finding strings that look like credentials and bad
at telling you which ones matter. Run one across a few dozen repositories and
it will hand you hundreds of findings, nearly all of them deliberate test
fixtures, documentation examples and vendored upstream code. People respond the
way anyone responds to an alarm that is usually wrong: they switch it off. The
exposure that follows is not caused by the absence of a scanner. It is caused by
the presence of an unreadable one.

So this package does not try to find more. It tries to be right about less.
"""

__version__ = "0.1.0"
