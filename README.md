# OWASP AntiSamy .NET

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4d5e15cf396e4d5ca659bd9d71f3f57d)](https://app.codacy.com/manual/spassarop/antisamy-dotnet?utm_source=github.com&utm_medium=referral&utm_content=spassarop/antisamy-dotnet&utm_campaign=Badge_Grade_Dashboard)
[![Actions Status](https://github.com/spassarop/antisamy-dotnet/workflows/CI/badge.svg)](https://github.com/spassarop/antisamy-dotnet/actions)
![CodeQL](https://github.com/spassarop/antisamy-dotnet/workflows/CodeQL/badge.svg)

A library for performing fast, configurable cleansing of HTML coming from untrusted sources. Refactored from an [old project in .NET Framework 2.0](https://wiki.owasp.org/index.php/Category:OWASP_AntiSamy_Project_.NET).

Another way of saying that could be: It's an API that helps you make sure that clients don't supply malicious cargo code in the HTML they supply for their profile, comments, etc., that get persisted on the server. The term "malicious code" in regard to web applications usually mean "JavaScript." Mostly, Cascading Stylesheets are only considered malicious when they invoke JavaScript. However, there are many situations where "normal" HTML and CSS can be used in a malicious manner.

This project will be trying to be in sync with the original Java version, its repository can be found [here](https://github.com/nahsra/antisamy).

## How to use

### 1. Import the dependency
Ways to import the project:

1.  Import the [NuGet package](https://www.nuget.org/packages/OWASP.AntiSamy/).
2.  Build and reference the OWASP.AntiSamy DLL in your project. 

### 2. Choosing a base policy file
Chances are that your site's use case for AntiSamy is at least roughly comparable to one of the predefined policy files. They each represent a "typical" scenario for allowing users to provide HTML (and possibly CSS) formatting information. Let's look into the different policy files:

#### 1) antisamy-slashdot.xml

Slashdot is a techie news site that allows users to respond anonymously to news posts with very limited HTML markup. Now, Slashdot is not only one of the coolest sites around, it's also one that's been subject to many different successful attacks. The rules for Slashdot are fairly strict: users can only submit the following HTML tags and no CSS: `<b>`, `<u>`, `<i>`, `<a>`, `<blockquote>`.

Accordingly, we've built a policy file that allows fairly similar functionality. All text-formatting tags that operate directly on the font, color or emphasis have been allowed.

#### 2) antisamy-ebay.xml

eBay is the most popular online auction site in the universe, as far as I can tell. It is a public site, so anyone is allowed to post listings with rich HTML content. It's not surprising that given the attractiveness of eBay as a target that it has been subject to a few complex XSS attacks. Listings are allowed to contain much more rich content than, say, Slashdot -- so it's attack surface is considerably larger. 

#### 3) antisamy-myspace.xml

MySpace was, at the time this project was born, the most popular social networking site. Users could submit pretty much all the HTML and CSS they wanted -- as long as it didn't contain JavaScript. MySpace was using a word blacklist to validate users' HTML, which is why they were subject to the infamous Samy worm. The Samy worm, which used fragmentation attacks combined with a word that should have been blacklisted (eval) - was the inspiration for this project.

#### 4) antisamy-anythinggoes.xml

I don't know of a possible use case for this policy file. If you wanted to allow every single valid HTML and CSS element (but without JavaScript or blatant CSS-related phishing attacks), you can use this policy file. Not even MySpace was this crazy. However, it does serve as a good reference because it contains base rules for every element, so you can use it as a knowledge base when using tailoring the other policy files.

### 3. Tailoring the policy file
You may want to deploy OWASP AntiSamy .NET in a default configuration, but it's equally likely that a site may want to have strict, business-driven rules for what users can allow. The discussion that decides the tailoring should also consider attack surface - which grows in relative proportion to the policy file.

When installing from the NuGet package, policy examples are included in your project **but not copied to the output folder by default**. If you decide to use one you can, for example in Visual Studio, select the chosen XML policy file and specify in its properties to be copied if newer or always. The example files are removed along with the package in case it's deleted. 

You may also want to enable/modify some "directives", which are basically advanced user options. Supported directives are the following:
-   `maxInputSize` (int): Maximum input size for the HTML to read.
-   `nofollowAnchors` (bool): Determines if adds the attribute `rel="nofollow"` on `<a>` tags.
-   `validateParamAsEmbed` (bool): Determines if validates the `<param>` tag as `<embed>` tag.
-   `preserveSpace` (bool): Determines if HTML output gets trimmed.
-   `preserveComments` (bool): Determines if comments are removed from the HTML.
-   `entityEncodeIntlChars` (bool): Determines if HTML output gets encoded regarding special characters, like accents.
-   `useXHTML` (bool): Determines if parser uses XHTML, explicitly used for CDATA handling when scanning CSS.
-   `onUnknownTag` (string): Determines the action for a detected unknown tag. Today, the only value taken into account is `"encode"`. Default action is `"remove"`.

More directives are supported on the Java-based project. For more detailed information on directive declaration and general policy format, inspect the example policies.
**Note**: Every input policy **will be validated** by AntiSamy against the only defined schema.

### 4. Calling the OWASP AntiSamy .NET API
Using OWASP AntiSamy .NET is easy. Here is an example of invoking AntiSamy with a policy file:

```c#
using OWASP.AntiSamy.Html;

Policy policy = Policy.GetInstance(POLICY_FILE_LOCATION);

var antiSamy = new AntiSamy();
CleanResults results = antiSamy.Scan(dirtyInput, policy);

MyUser.StoreHtmlProfile(results.GetCleanHTML()); // Some custom function
```

There are a few ways to create a `Policy` object. The `GetInstance()` method can take any of the following:

-   A `string` filename.
-   A `FileInfo` object.
-   A `Stream` object.
-   `Policy` files can also be referenced by filename by passing a second argument to the `AntiSamy.Scan()` method as the following examples show:

```c#
var antiSamy = new AntiSamy();
CleanResults results = antiSamy.Scan(dirtyInput, policyFilePath);
```

### 5. Analyzing CleanResults
The `CleanResults` object provides a lot of useful stuff.

-   `GetCleanHTML()` - the clean, safe HTML output.
-   `GetErrorMessages()` - a list of String error messages. -- *if this returns empty that does not mean there were no attacks!*
-   `GetNumberOfErrors()` - the error message count in case the list itself is not needed. -- *if this returns 0 that does not mean there were no attacks!*
-   `GetScanTime()` - returns the scan time in seconds.
-   `GetStartOfScan()` and `GetEndOfScan()` - return the each `DateTime` object in case it is needed.
 
**Important note**: There has been much confusion about the `GetErrorMessages()` method. The `GetErrorMessages()` method does not subtly answer the question "is this safe input?" in the affirmative if it returns an empty list. You must always use the sanitized input and there is no way to be sure the input passed in had no attacks.

The serialization and deserialization process that is critical to the effectiveness of the sanitizer is purposefully lossy and will filter out attacks via several attack vectors. Unfortunately, one of the tradeoffs of this strategy is that we don't always know in retrospect that an attack was seen. Thus, the `GetErrorMessages()` API is there to help users understand their well-intentioned input meet the requirements of the system, not help a developer detect if an attack was present. 

## Contributing to OWASP AntiSamy .NET

### Found an issue?
If you have found a bug, then create an issue in the OWASP AntiSamy .NET repository: <https://github.com/spassarop/antisamy-dotnet/issues>.

### Found a vulnerability?
If you have found a vulnerability in OWASP AntiSamy .NET, first search the issues list (see above) to see if it has already been reported. If it has not, then please contact Sebastián Passaro (sebastian.passaro at owasp.org) directly. Please do not report vulnerabilities via GitHub issues as we wish to keep our users secure while a patch is implemented and deployed. If you wish to be acknowledged for finding the vulnerability, then please follow this process.

More detail is available in the file: [SECURITY.md](https://github.com/spassarop/antisamy-dotnet/blob/master/SECURITY.md).

## How to build
You can build and test from source pretty easily:
```bash
git clone https://github.com/spassarop/antisamy-dotnet.git
cd antisamy-dotnet
dotnet build OWASP.AntiSamy.sln
```

To build without tests:
```
dotnet build OWASP.AntiSamy/OWASP.AntiSamy.csproj
```

Also, you always can just build the project/solution from Visual Studio.

## How to test
To run the tests:
```
dotnet test OWASP.AntiSamy.sln
```

## Supported platforms
-   .NET Framework 4.6+
-   .NET Core 2.0+
-   .NET Standard 2.0
-   .NET 5.0
-   .NET 6.0

## Dependencies
Core:
-   AngleSharp (v0.16.1)
-   AngleSharp.Css (v0.16.3)
-   HtmlAgilityPack (v1.11.40)

Tests:
-   FluentAssertions (v5.10.3)
-   Microsoft.NET.Test.Sdk (v17.0.0)
-   NUnit (v3.13.2)
-   NUnit3TestAdapter (v4.2.1)

## License
Released under the [BSD-3-Clause](https://opensource.org/licenses/BSD-3-Clause) license as specified here: [LICENSE](https://github.com/spassarop/antisamy-dotnet/blob/master/LICENSE). 
