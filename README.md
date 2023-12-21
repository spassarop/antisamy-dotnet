# OWASP AntiSamy .NET

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4d5e15cf396e4d5ca659bd9d71f3f57d)](https://app.codacy.com/manual/spassarop/antisamy-dotnet?utm_source=github.com&utm_medium=referral&utm_content=spassarop/antisamy-dotnet&utm_campaign=Badge_Grade_Dashboard)
[![Actions Status](https://github.com/spassarop/antisamy-dotnet/workflows/CI/badge.svg)](https://github.com/spassarop/antisamy-dotnet/actions)
![CodeQL](https://github.com/spassarop/antisamy-dotnet/workflows/CodeQL/badge.svg)

A library for performing fast, configurable cleansing of HTML coming from untrusted sources. Refactored from an [old project in .NET Framework 2.0](https://wiki.owasp.org/index.php/Category:OWASP_AntiSamy_Project_.NET).

Another way of saying that could be: It's an API that helps you make sure that clients don't supply malicious cargo code in the HTML they supply for their profile, comments, etc., that get persisted on the server. The term "malicious code" in regard to web applications usually mean "JavaScript." Mostly, Cascading Stylesheets are only considered malicious when they invoke JavaScript. However, there are many situations where "normal" HTML and CSS can be used in a malicious manner.

This project will be trying to be in sync with the original Java version, its repository can be found [here](https://github.com/nahsra/antisamy).

Check the [wiki](https://github.com/spassarop/antisamy-dotnet/wiki) for information on how to use, build, test and more.

**Important note**: Since 1.2.0 the example policy files that were previously included in the NuGet package are removed. Each developer/deployer must manually place a policy in a location of their choice. For mor information about policies, refer to the wiki mentioned above.

## Contributing to OWASP AntiSamy .NET

### Found an issue?
If you have found a bug, then create an issue in the OWASP AntiSamy .NET repository: <https://github.com/spassarop/antisamy-dotnet/issues>.

### Found a vulnerability?
If you have found a vulnerability in OWASP AntiSamy .NET, first search the issues list (see above) to see if it has already been reported. If it has not, then please contact Sebastián Passaro (sebastian.passaro at owasp.org) directly. Please do not report vulnerabilities via GitHub issues as we wish to keep our users secure while a patch is implemented and deployed. If you wish to be acknowledged for finding the vulnerability, then please follow this process.

More detail is available in the file: [SECURITY.md](https://github.com/spassarop/antisamy-dotnet/blob/master/SECURITY.md).

## License
Released under the [BSD-3-Clause](https://opensource.org/licenses/BSD-3-Clause) license as specified here: [LICENSE](https://github.com/spassarop/antisamy-dotnet/blob/master/LICENSE). 
