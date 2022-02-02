/*
 * Copyright (c) 2022, Jerry Hoff, Caner Patir, Sebastián Passaro
 * 
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of OWASP nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AngleSharp;
using AngleSharp.Css;
using AngleSharp.Css.Dom;
using AngleSharp.Css.Parser;
using AngleSharp.Css.Values;
using AngleSharp.Dom;
using AngleSharp.Io;
using OWASP.AntiSamy.Exceptions;
using OWASP.AntiSamy.Html;
using OWASP.AntiSamy.Html.Model;
using OWASP.AntiSamy.Html.Scan;
using OWASP.AntiSamy.Html.Util;

namespace OWASP.AntiSamy.Css
{
    /// <summary> Encapsulates the parsing and validation of a CSS style sheet or inline declaration. 
    /// To make use of this class, instantiate the scanner with the desired policy and call either 
    /// <see cref="ScanInlineStyle(string, string)"/> or <see cref="ScanStyleSheet(string)"/> as appropriate.
    /// </summary>
    internal class CssScanner
    {
        private const string DUMMY_SELECTOR_BEGIN = ".dummySelector {";
        private const string DUMMY_SELECTOR_END = "}";

        private readonly Regex CDATA_REGEX = new Regex(@"^\s*<!\[CDATA\[(.*)\]\]>\s*$", RegexOptions.Compiled | RegexOptions.Singleline);
        private readonly Regex CSS_UNICODE_ESCAPES_REGEX = new Regex(@"\\([0-9a-fA-F]{1,6})\s?|\\([^\r\n\f0-9a-fA-F'""{};:()#*])", RegexOptions.Compiled);
        private readonly Regex CSS_COMMENTS_REGEX = new Regex(@"/\*.*?\*/", RegexOptions.Compiled);
        private readonly Regex DANGEROUS_CSS_EXPRESSION_REGEX = new Regex(
            @"[eE\uFF25\uFF45][xX\uFF38\uFF58][pP\uFF30\uFF50][rR\u0280\uFF32\uFF52][eE\uFF25\uFF45][sS\uFF33\uFF53]{2}[iI\u026A\uFF29\uFF49][oO\uFF2F\uFF4F][nN\u0274\uFF2E\uFF4E]", RegexOptions.Compiled);

        /// <summary>The parser to be used in any scanning.</summary>
        private readonly CssParser parser;

        /// <summary>The policy file to be used in any scanning.</summary>
        private readonly Policy policy;

        private string CurrentTagName { get; set; }
        private int SizeLimit { get; set; }
        private List<string> ErrorMessages { get; set; }
        private Dictionary<string, ICssStyleSheet> ScannedImportedStyleSheets { get; set; }

        /// <summary> Constructs a scanner based on the given policy.</summary>
        /// <param name="policy">The policy to follow when scanning.</param>
        public CssScanner(Policy policy)
        {
            this.policy = policy;

            // FIX: Leave this in case there is no solution, hex is better that lots of rgb/a autoconversions.
            // Set UseHex to true to preserve Hex color format on CSS and avoid rgba() conversion
            //var colorType = typeof(CssKeywords).Assembly.GetType("AngleSharp.Css.Values.Color");
            //var useHex = colorType.GetProperty("UseHex", BindingFlags.Public | BindingFlags.Static);
            //useHex.SetValue(null, true);

            var cssParserOptions = new CssParserOptions
            {
                IsIncludingUnknownDeclarations = true,
                IsIncludingUnknownRules = true,
                IsToleratingInvalidSelectors = true
            };
            IBrowsingContext browsingContext = BrowsingContext.New(Configuration.Default
                .WithCss()
                .With(new DefaultHttpRequester(userAgent: null, setup: SetupHttpRequest))
                .WithDefaultLoader(new LoaderOptions { IsResourceLoadingEnabled = true }));
            parser = new CssParser(cssParserOptions, browsingContext);
        }

        /// <summary> Scans the contents of a full style sheet (ex. a file based style sheet or
        /// the complete style sheet contents as declared within &lt;style&gt; tags).</summary>
        /// <param name="taintedCss">A string containing the contents of the CSS style sheet to validate</param>
        /// <returns>A <see cref="CleanResults"/> object containing the results of the scan.</returns>
        /// <exception cref="ScanException"/>
        /// <exception cref="ParseException"/>
        public CleanResults ScanStyleSheet(string taintedCss)
        {
            return DoScan(taintedCss, isInlineCss: false, tagName: null);
        }

        /// <summary> Scans the contents of an inline style declaration (ex. in the style attribute of an HTML tag) 
        /// and validates the style sheet according to this <see cref="CssScanner"/>'s policy file.</summary>
        /// <param name="taintedCss">A string containing the contents of the CSS styles heet to validate.</param>
        /// <param name="tagName">The name of the tag for which this inline style was declared.</param>
        /// <returns>A <see cref="CleanResults"/> object containing the results of the scan.</returns>
        /// <exception cref="ScanException"/>
        /// <exception cref="ParseException"/>
        public CleanResults ScanInlineStyle(string taintedCss, string tagName)
        {
            return DoScan(taintedCss, isInlineCss: true, tagName: tagName);
        }

        /// <summary> Does the actual scan.</summary>
        /// <param name="taintedCss">A string containing the contents of the CSS style sheet to validate.</param>
        /// <param name="isInlineCss">A boolean specifying if the style to parse is inline.</param>
        /// <param name="tagName">In case of inline style, the tag name where the attribute is located. 
        /// Provide <see langword="null"/> or empty string otherwise.</param>
        /// <exception cref="ScanException"/>
        /// <exception cref="ParseException"/>
        private CleanResults DoScan(string taintedCss, bool isInlineCss, string tagName)
        {
            CurrentTagName = tagName;
            var startOfScan = new DateTime();
            ErrorMessages = new List<string>();
            ScannedImportedStyleSheets = new Dictionary<string, ICssStyleSheet>();
            SizeLimit = policy.MaxInputSize;
            string cleanStylesheet;

            // Check to see if the text starts with (\s)*<![CDATA[ and ends with ]]> (\s)*.
            var match = CDATA_REGEX.Match(taintedCss);
            bool isCData = match.Success;
            if (isCData)
            {
                taintedCss = match.Groups[1].Value;
            }

            try
            {
                ICssStyleSheet styleSheet;
                try
                {
                    styleSheet = parser.ParseStyleSheet(isInlineCss ? $"{DUMMY_SELECTOR_BEGIN}{taintedCss}{DUMMY_SELECTOR_END}" : taintedCss);
                    if (policy.EmbedsStyleSheets) {
                        // Parsing again exclusively for import rules (others are internally skipped)
                        using (Task<IDocument> documentTask = styleSheet.Context.OpenAsync(req => req.Content(styleSheet.ToCss())))
                        {
                            documentTask.Wait();
                            IDocument document = documentTask.Result;
                            styleSheet.SetOwner(document.DocumentElement);
                        }

                        using (Task<ICssStyleSheet> styleSheetTask = parser.ParseStyleSheetAsync(styleSheet, CancellationToken.None))
                        {
                            styleSheetTask.Wait();
                            styleSheet = styleSheetTask.Result;
                        }
                    }
                }
                catch (Exception ex)
                {
                    throw new ParseException(ex.Message, ex);
                }

                ScanStyleSheet(styleSheet);
                string result = StringifyStyleSheet(styleSheet);
                cleanStylesheet = (isInlineCss ? CleanDummyWrapper(result) : result).Trim();
            }
            catch (Exception ex)
            {
                if (ex is ParseException)
                {
                    throw;
                }
                else
                {
                    throw new ScanException($"An error occured while scanning CSS: {ex.Message}", ex);
                }
            }

            if (isCData && !policy.UsesXhtml)
            {
                cleanStylesheet = $"<![CDATA[[{cleanStylesheet}]]>";
            }

            return new CleanResults(startOfScan, new DateTime(), cleanStylesheet, ErrorMessages);
        }

        /// <summary> Removes the "dummy" wrapper around the inline CSS.</summary>
        /// <param name="wrappedStyle">The style string to be unwrapped.</param>
        private string CleanDummyWrapper(string wrappedStyle)
        {
            if (wrappedStyle.StartsWith(DUMMY_SELECTOR_BEGIN))
            {
                wrappedStyle = wrappedStyle.Replace(DUMMY_SELECTOR_BEGIN, string.Empty);

                if (wrappedStyle.EndsWith("}"))
                {
                    wrappedStyle = wrappedStyle.Remove(wrappedStyle.Length - 1);
                }
            }
            return string.IsNullOrWhiteSpace(wrappedStyle) ? string.Empty : wrappedStyle;
        }

        /// <summary>Scans a CSS style sheet and returns a clean output removing invalid rules or properties.</summary>
        /// <param name="styleSheet">The CSS style sheet to scan.</param>
        /// <returns>A clean CSS style sheet as string.</returns>
        private void ScanStyleSheet(ICssStyleSheet styleSheet)
        {
            var i = 0;
            while (i < styleSheet.Rules.Length)
            {
                ICssRule rule = styleSheet.Rules[i];
                if (!ScanStyleRule(rule))
                {
                    AddError(Constants.ERROR_CSS_RULE_NOTALLOWED, rule.CssText);
                    styleSheet.RemoveAt(i); // Deletes rule in-place (length is dynamic), counter must not be incremented.
                }
                else
                {
                    i++;
                }
            }
        }

        /// <summary>Gets the string representation of a CSS style sheet.</summary>
        /// <param name="styleSheet">The CSS style sheet to stringify.</param>
        /// <param name="isMainStyleSheet">If the style sheet is the one scanned, 
        /// use <c>false</c> if it is an imported style sheet.</param>
        /// <returns>A CSS style sheet as string.</returns>
        private string StringifyStyleSheet(ICssStyleSheet styleSheet, bool isMainStyleSheet = true)
        {
            var stringWriter = new StringWriter();
            styleSheet.ToCss(stringWriter, new CssStyleFormatter());
            string result = stringWriter.GetStringBuilder().ToString();

            if (policy.EmbedsStyleSheets && isMainStyleSheet)
            {
                foreach (KeyValuePair<string, ICssStyleSheet> imported in ScannedImportedStyleSheets)
                {
                    result = result.Replace(imported.Key, StringifyStyleSheet(imported.Value, isMainStyleSheet: false));
                }
            }

            return result;
        }

        /// <summary>Scans a CSS rule and tells if it is valid. Even if it is valid, internally it 
        /// may have some of its properties removed if they dangerous parts are detected.</summary>
        /// <param name="rule">The CSS rule to scan.</param>
        /// <returns><c>true</c> if the rule is valid, <c>false</c> if it must be removed.</returns>
        private bool ScanStyleRule(ICssRule rule)
        {
            if (rule is ICssStyleRule styleRule)
            {
                ScanStyleDeclaration(styleRule.Style);
            }
            else if (rule is ICssGroupingRule groupingRule)
            {
                foreach (ICssRule childRule in groupingRule.Rules)
                {
                    ScanStyleRule(childRule);
                }
            }
            else if (rule is ICssPageRule pageRule)
            {
                ScanStyleDeclaration(pageRule.Style);
            }
            else if (rule is ICssKeyframesRule keyFramesRule)
            {
                foreach (ICssKeyframeRule childRule in keyFramesRule.Rules.OfType<ICssKeyframeRule>().ToList())
                {
                    ScanStyleRule(childRule);
                }
            }
            else if (rule is ICssKeyframeRule keyFrameRule)
            {
                ScanStyleDeclaration(keyFrameRule.Style);
            }
            else if (rule is ICssImportRule importRule && policy.EmbedsStyleSheets)
            {
                if (importRule.Sheet == null)
                {
                    AddError(Constants.ERROR_CSS_IMPORT_FAILURE, HtmlEntityEncoder.HtmlEntityEncode(importRule.Href));
                    return false;
                }

                if (ScannedImportedStyleSheets.Count == policy.MaxStyleSheetImports)
                {
                    AddError(Constants.ERROR_CSS_IMPORT_EXCEEDED, 
                        HtmlEntityEncoder.HtmlEntityEncode(importRule.Href),
                        policy.MaxStyleSheetImports);
                    return false;
                }

                int sheetLength = importRule.Sheet.ToCss().Length;
                if (sheetLength > SizeLimit)
                {
                    AddError(Constants.ERROR_CSS_IMPORT_TOOLARGE, 
                        HtmlEntityEncoder.HtmlEntityEncode(importRule.Href), 
                        policy.MaxInputSize);
                    return false;
                }

                SizeLimit -= sheetLength;
                ScanStyleSheet(importRule.Sheet);
                ScannedImportedStyleSheets.Add(importRule.ToCss(), importRule.Sheet);
            }
            else
            {
                return false; // Don't allow any other rules for now
            }

            return true;
        }

        /// <summary>Scans a CSS style declaration and removes disallowed properties if needed.</summary>
        /// <param name="styleDeclaration">The style declaration to clean.</param>
        private void ScanStyleDeclaration(ICssStyleDeclaration styleDeclaration)
        {
            var removingProperties = new List<Tuple<ICssProperty, string>>();

            foreach (ICssProperty cssProperty in styleDeclaration)
            {
                string decodedName = DecodeCss(cssProperty.Name);
                string decodedValue = DecodeCss(cssProperty.Value);
                
                Property allowedCssProperty = policy.GetPropertyByName(decodedName);

                if (allowedCssProperty == null || DANGEROUS_CSS_EXPRESSION_REGEX.IsMatch(decodedValue))
                {
                    removingProperties.Add(new Tuple<ICssProperty, string>(cssProperty, GetPropertyErrorMessage(decodedName, decodedValue)));
                }
                else if (cssProperty.RawValue != null)
                {
                    ICssValue value = cssProperty.RawValue;
                    ValidateValue(removingProperties, cssProperty, allowedCssProperty, value);
                }
            }

            foreach (Tuple<ICssProperty, string> style in removingProperties)
            {
                styleDeclaration.RemoveProperty(style.Item1.Name);
                ErrorMessages.Add(style.Item2);
            }
        }

        private void ValidateValue(List<Tuple<ICssProperty, string>> removingProperties, ICssProperty cssProperty, Property allowedCssProperty, ICssValue value)
        {
            string decodedValue = DecodeCss(RemoveQuotesIfUrlValue(value));

            if (value is ICssMultipleValue multipleValues)
            {
                foreach (ICssValue singleValue in multipleValues)
                {
                    string decodedSingleValue = DecodeCss(RemoveQuotesIfUrlValue(singleValue));
                    if (!IsValidValue(allowedCssProperty, cssProperty, decodedSingleValue, removingProperties))
                    {
                        removingProperties.Add(new Tuple<ICssProperty, string>(cssProperty,
                            ErrorMessageUtil.GetMessage(Constants.ERROR_CSS_PROPERTY_VALUE_INVALID,
                            HtmlEntityEncoder.HtmlEntityEncode(decodedSingleValue), 
                            HtmlEntityEncoder.HtmlEntityEncode(decodedValue))));
                        return;
                    }
                }
            }
            else if (!IsValidValue(allowedCssProperty, cssProperty, decodedValue, removingProperties))
            {
                removingProperties.Add(new Tuple<ICssProperty, string>(cssProperty, 
                    ErrorMessageUtil.GetMessage(Constants.ERROR_CSS_PROPERTY_VALUE_INVALID, HtmlEntityEncoder.HtmlEntityEncode(decodedValue))));
            }
        }

        /// <summary>Validates if the provided <c>value</c> is allowed in the CSS property.
        /// It checks against allowed literal values and regular expressions, if the <c>value</c>
        /// is not allowed, the <c>cssProperty</c> is added to the <c>removeStyles</c> list.</summary>
        /// <param name="allowedCssProperty">The policy CSS property.</param>
        /// <param name="cssProperty">The CSS property which might be removed.</param>
        /// <param name="value">The literal value to check.</param>
        /// <param name="removingProperties">The collection of CSS properties to be removed.</param>
        private bool IsValidValue(Property allowedCssProperty, ICssProperty cssProperty, string value, List<Tuple<ICssProperty, string>> removingProperties)
        {
            if (allowedCssProperty.AllowedValues.Any() && allowedCssProperty.AllowedValues.Any(lit => lit.Equals(value, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            if (allowedCssProperty.AllowedRegExp.Any() && allowedCssProperty.AllowedRegExp.Any(regex => new Regex($"^{regex}$").IsMatch(value)))
            {
                return true;
            }

            foreach (string shortHandRef in allowedCssProperty.ShorthandRefs)
            {
                Property shorthand = policy.GetPropertyByName(shortHandRef);
                if (shorthand != null && IsValidValue(shorthand, cssProperty, value, removingProperties))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>Decodes unicode characters and removes comments from a CSS string based on 
        /// <see cref="CSS_UNICODE_ESCAPES_REGEX"/> and <see cref="CSS_COMMENTS_REGEX"/> regular expressions.</summary>
        /// <param name="css">The CSS string to decode.</param>
        /// <returns>The CSS decoded and without comments.</returns>
        private string DecodeCss(string css)
        {
            string intermediateResult = CSS_UNICODE_ESCAPES_REGEX.Replace(css, match =>
            {
                if (match.Groups[1].Success)
                {
                    return ((char)int.Parse(match.Groups[1].Value, NumberStyles.HexNumber)).ToString();
                }
                string text = match.Groups[2].Value;
                return text == "\\" ? @"\\" : text;
            });

            return CSS_COMMENTS_REGEX.Replace(intermediateResult, match => string.Empty);
        }

        /// <summary>If the CSS parser recognizes the value as an URL, this method builds a value of the form
        /// <c>url(newVlaue)</c>, where <c>newValue</c> is the original URL value but without surrounding quotes.</summary>
        /// <remarks>Note: This method was created to match the behavior of OWASP AntiSamy Java version,
        /// were the parser removes the quotes automatically. This parser adds them, so there is no common point.
        /// Also, the default allowed regular expressions don't have quotes, so any parser behavior becomes contradictory.</remarks>
        /// <param name="value">The <see cref="ICssValue"/> that may be an URL.</param>
        /// <returns>A string with the unquoted URL value or the original value if it is not an URL.</returns>
        private string RemoveQuotesIfUrlValue(ICssValue value)
        {
            string valueAsUrl = value.AsUrl();
            return string.IsNullOrEmpty(valueAsUrl) ? value.CssText : $"url({valueAsUrl})";
        }

        private string GetPropertyErrorMessage(string propertyName, string propertyValue)
        {
            if (string.IsNullOrEmpty(CurrentTagName))
            {
                return ErrorMessageUtil.GetMessage(Constants.ERROR_CSS_STYLESHEET_PROPERTY_INVALID,
                    HtmlEntityEncoder.HtmlEntityEncode($"{propertyName}: {propertyValue}"));
            }
            else
            {
                return ErrorMessageUtil.GetMessage(Constants.ERROR_CSS_TAG_PROPERTY_INVALID,
                    CurrentTagName, HtmlEntityEncoder.HtmlEntityEncode($"{propertyName}: {propertyValue}"));
            }
        }

        private void SetupHttpRequest(HttpWebRequest httpWebRequest)
        {
            httpWebRequest.Timeout = policy.ConnectionTimeout;
        }

        private void AddError(string errorKey, params object[] arguments)
        {
            ErrorMessages.Add(ErrorMessageUtil.GetMessage(errorKey, arguments));
        }
    }
}
