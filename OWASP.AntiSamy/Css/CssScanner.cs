/*
* Copyright (c) 2020, Jerry Hoff
* 
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without 
* modification, are permitted provided that the following conditions are met:
* - Redistributions of source code must retain the above copyright notice, 
* 	 this list of conditions and the following disclaimer.
* - Redistributions in binary form must reproduce the above copyright notice,
*   this list of conditions and the following disclaimer in the documentation
*   and/or other materials provided with the distribution.
* - Neither the name of OWASP nor the names of its contributors may be used to
*   endorse or promote products derived from this software without specific
*   prior written permission.
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
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using AngleSharp.Css;
using AngleSharp.Css.Dom;
using AngleSharp.Css.Parser;
using OWASP.AntiSamy.Exceptions;
using OWASP.AntiSamy.Html;
using OWASP.AntiSamy.Html.Model;

namespace OWASP.AntiSamy.Css
{
    /// <summary> Encapsulates the parsing and validation of a CSS style sheet or inline declaration. 
    /// To make use of this class, instantiate the scanner with the desired policy and call either 
    /// <see cref="ScanInlineStyle(string, string, int)"/> or <see cref="ScanStyleSheet(string, int)"/> as appropriate.
    /// </summary>
    public class CssScanner
    {
        private const string DUMMY_SELECTOR_BEGIN = ".dummySelector {";
        private const string DUMMY_SELECTOR_END = " }";

        private readonly Regex SCHEME_REGEX = new Regex(@"^\s*([^\/#]*?)(?:\:|&#0*58|&#x0*3a)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private readonly Regex CSS_URL_REGEX = new Regex(@"[Uu][Rr\u0280][Ll\u029F]\s*\(\s*(['""]?)\s*([^'"")\s]+)\s*(['""]?)\s*", RegexOptions.Compiled);
        private readonly Regex CSS_UNICODE_ESCAPES_REGEX = new Regex(@"\\([0-9a-fA-F]{1,6})\s?|\\([^\r\n\f0-9a-fA-F'""{};:()#*])", RegexOptions.Compiled);
        private readonly Regex CSS_COMMENTS_REGEX = new Regex(@"/\*.*?\*/", RegexOptions.Compiled);
        private readonly Regex DANGEROUS_CSS_EXPRESSION_REGEX = new Regex(
            @"[eE\uFF25\uFF45][xX\uFF38\uFF58][pP\uFF30\uFF50][rR\u0280\uFF32\uFF52][eE\uFF25\uFF45][sS\uFF33\uFF53]{2}[iI\u026A\uFF29\uFF49][oO\uFF2F\uFF4F][nN\u0274\uFF2E\uFF4E]", RegexOptions.Compiled);

        /// <summary>The parser to be used in any scanning.</summary>
        private readonly CssParser parser = new CssParser(new CssParserOptions
        {
            IsIncludingUnknownDeclarations = true,
            IsIncludingUnknownRules = true,
            IsToleratingInvalidSelectors = true
        });

        /// <summary>The policy file to be used in any scanning.</summary>
        private readonly Policy policy;

        /// <summary> Constructs a scanner based on the given policy.</summary>
        /// <param name="policy">The policy to follow when scanning.</param>
        public CssScanner(Policy policy)
        {
            this.policy = policy;
        }

        /// <summary> Scans the contents of a full style sheet (ex. a file based style sheet or
        /// the complete style sheet contents as declared within &lt;style&gt; tags).</summary>
        /// <param name="taintedCss">A string containing the contents of the CSS style sheet to validate</param>
        /// <returns>A <see cref="CleanResults"/> object containing the results of the scan.</returns>
        /// <exception cref="ScanException"/>
        /// <exception cref="ParseException"/>
        public CleanResults ScanStyleSheet(string taintedCss, int sizeLimit)
        {
            // TODO: Do something about sizeLimit
            return DoScan(taintedCss, isInlineCss: false);
        }

        /// <summary> Scans the contents of an inline style declaration (ex. in the style attribute of an HTML tag) 
        /// and validates the style sheet according to this <see cref="CssScanner"/>'s policy file.</summary>
        /// <param name="taintedCss">A string containing the contents of the CSS styles heet to validate.</param>
        /// <param name="tagName">The name of the tag for which this inline style was declared.</param>
        /// <returns>A <see cref="CleanResults"/> object containing the results of the scan.</returns>
        /// <exception cref="ScanException"/>
        /// <exception cref="ParseException"/>
        public CleanResults ScanInlineStyle(string taintedCss, string tagName, int sizeLimit)
        {
            // TODO: Do something about tagName (probably delete it later)
            return DoScan(taintedCss, isInlineCss: true);
        }

        /// <summary> Does the actual scan.</summary>
        /// <param name="taintedCss">A string containing the contents of the CSS style sheet to validate.</param>
        /// <param name="isInlineCss">A boolean specifying if the style to parse is inline.</param>
        /// <exception cref="ScanException"/>
        /// <exception cref="ParseException"/>
        private CleanResults DoScan(string taintedCss, bool isInlineCss)
        {
            var startOfScan = new DateTime();
            var errorMessages = new List<string>();
            string cleanStylesheet;

            try
            {
                ICssStyleSheet styleSheet;
                try
                {
                    styleSheet = parser.ParseStyleSheet(isInlineCss ? $"{DUMMY_SELECTOR_BEGIN}{taintedCss}{DUMMY_SELECTOR_END}" : taintedCss);
                }
                catch (Exception ex)
                {
                    throw new ParseException(ex.Message, ex);
                }

                string result = ScanStyleSheet(styleSheet, errorMessages);
                cleanStylesheet = isInlineCss ? CleanDummyWrapper(result) : result;
            }
            catch (ParseException)
            {
                throw;
            }
            catch (Exception exception)
            {
                throw new ScanException("An error occured while scanning CSS", exception);
            }

            return new CleanResults(startOfScan, new DateTime(), cleanStylesheet, null, errorMessages);
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
        /// <param name="errorMessages">Cumulative error messages list.</param>
        /// <returns>A clean CSS style sheet as string.</returns>
        private string ScanStyleSheet(ICssStyleSheet styleSheet, List<string> errorMessages)
        {
            for (var i = 0; i < styleSheet.Rules.Length;)
            {
                ICssRule rule = styleSheet.Rules[i];
                if (!ScanStyleRule(rule, errorMessages))
                {
                    styleSheet.RemoveAt(i);
                }
                else
                {
                    i++;
                }
            }

            var stringWriter = new StringWriter();
            styleSheet.ToCss(stringWriter, new CssStyleFormatter());
            return stringWriter.GetStringBuilder().ToString();
        }

        /// <summary>Scans a CSS rule and tells if it is valid. Even if it is valid, internally it 
        /// may have some of its properties removed if they dangerous parts are detected.</summary>
        /// <param name="rule">The CSS rule to scan.</param>
        /// <param name="errorMessages">Cumulative error messages list.</param>
        /// <returns><c>true</c> if the rule is valid, <c>false</c> if it must be removed.</returns>
        private bool ScanStyleRule(ICssRule rule, List<string> errorMessages)
        {
            if (rule is ICssStyleRule styleRule)
            {
                ScanStyleDeclaration(styleRule.Style, errorMessages);
            }
            else if (rule is ICssGroupingRule groupingRule)
            {
                foreach (ICssRule childRule in groupingRule.Rules)
                {
                    ScanStyleRule(childRule, errorMessages);
                }
            }
            else if (rule is ICssPageRule pageRule)
            {
                ScanStyleDeclaration(pageRule.Style, errorMessages);
            }
            else if (rule is ICssKeyframesRule keyFramesRule)
            {
                foreach (ICssKeyframeRule childRule in keyFramesRule.Rules.OfType<ICssKeyframeRule>().ToList())
                {
                    ScanStyleRule(childRule, errorMessages);
                }
            }
            else if (rule is ICssKeyframeRule keyFrameRule)
            {
                ScanStyleDeclaration(keyFrameRule.Style, errorMessages);
            }
            else if (rule is ICssImportRule importRule)
            {
                return false; // Don't allow import rules for now
            }

            return true;
        }

        /// <summary>Scans a CSS style declaration and removes disallowed properties if needed.</summary>
        /// <param name="styleDeclaration">The style declaration to clean.</param>
        /// <param name="errorMessages">Cumulative error messages list.</param>
        private void ScanStyleDeclaration(ICssStyleDeclaration styleDeclaration, List<string> errorMessages)
        {
            var removingProperties = new List<Tuple<ICssProperty, string>>();

            foreach (ICssProperty cssProperty in styleDeclaration)
            {
                string key = DecodeCss(cssProperty.Name);
                string value = DecodeCss(cssProperty.Value);
                Property allowedCssProperty = policy.GetPropertyByName(key);

                if (allowedCssProperty == null)
                {
                    removingProperties.Add(new Tuple<ICssProperty, string>(cssProperty, $"CSS property \"{key}\" is not allowed"));
                    continue;
                }

                if (DANGEROUS_CSS_EXPRESSION_REGEX.IsMatch(value))
                {
                    removingProperties.Add(new Tuple<ICssProperty, string>(cssProperty, $"\"{value}\" is invalid CSS expression"));
                    continue;
                }

                ValidateValue(allowedCssProperty, cssProperty, value, removingProperties);
                MatchCollection urls = CSS_URL_REGEX.Matches(value);

                if (urls.Count > 0 && !urls.Cast<Match>().All(u => SCHEME_REGEX.IsMatch(u.Value)))
                {
                    removingProperties.Add(new Tuple<ICssProperty, string>(cssProperty, "Illegal URL detected."));
                }
            }

            foreach (Tuple<ICssProperty, string> style in removingProperties)
            {
                styleDeclaration.RemoveProperty(style.Item1.Name);
                errorMessages.Add(style.Item2);
            }
        }

        /// <summary>Validates if the provided <c>value</c> is allowed in the CSS property.
        /// It checks against allowed literal values and regular expressions, if the <c>value</c>
        /// is not allowed, the <c>cssProperty</c> is added to the <c>removeStyles</c> list.</summary>
        /// <param name="allowedCssProperty">The policy CSS property.</param>
        /// <param name="cssProperty">The CSS property which might be removed.</param>
        /// <param name="value">The literal value to check.</param>
        /// <param name="removeStyles">The collection of CSS properties to be removed.</param>
        private void ValidateValue(Property allowedCssProperty, ICssProperty cssProperty, string value, List<Tuple<ICssProperty, string>> removeStyles)
        {
            if (allowedCssProperty.AllowedValues.Any() && !allowedCssProperty.AllowedValues.Any(lit => lit.Equals(value, StringComparison.OrdinalIgnoreCase)))
            {
                removeStyles.Add(new Tuple<ICssProperty, string>(cssProperty, $"\"{value}\" is not allowed literal"));
                return;
            }

            if (allowedCssProperty.AllowedRegExp.Any() && !allowedCssProperty.AllowedRegExp.Any(regex => new Regex(regex).IsMatch(value)))
            {
                removeStyles.Add(new Tuple<ICssProperty, string>(cssProperty, $"\"{value}\" is not allowed literal by regex"));
                return;
            }

            foreach (string shortHandRef in allowedCssProperty.ShorthandRefs)
            {
                Property shorthand = policy.GetPropertyByName(shortHandRef);
                if (shorthand != null)
                {
                    ValidateValue(shorthand, cssProperty, value, removeStyles);
                }
            }
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
    }
}