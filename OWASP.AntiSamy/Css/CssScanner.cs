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

    /// <summary> Encapsulates the parsing and validation of a CSS stylesheet or inline
    /// declaration. To make use of this class, instantiate the scanner with the
    /// desired policy and call either <code>scanInlineSheet()</code> or
    /// <code>scanStyleSheet</code> as appropriate.
    /// 
    /// </summary>
    /// <seealso cref="scanInlineStyle(String, String)">
    /// </seealso>
    /// <seealso cref="scanStyleSheet(String)">
    /// 
    /// </seealso>

    public class CssScanner
    {
        private const string DUMMY_SELECTOR_BEGIN = ".dummySelector {";
        private const string DUMMY_SELECTOR_END = " }";
        private static int DEFAULT_TIMEOUT = 1000;

        /// <summary> The parser to be used in any scanning</summary>
        private CssParser parser = new CssParser(new CssParserOptions
        {
            IsIncludingUnknownDeclarations = true,
            IsIncludingUnknownRules = true,
            IsToleratingInvalidSelectors = true
        });

        /// <summary> The policy file to be used in any scanning</summary>
        private Policy policy;

        /// <summary> Constructs a scanner based on the given policy.
        /// 
        /// </summary>
        /// <param name="policy">the policy to follow when scanning
        /// </param>
        public CssScanner(Policy policy)
        {
            this.policy = policy;
        }

        /// <summary> Scans the contents of a full stylesheet (ex. a file based stylesheet or
        /// the complete stylesheet contents as declared within &lt;style&gt; tags)
        /// 
        /// </summary>
        /// <param name="taintedCss">a <code>String</code> containing the contents of the CSS
        /// stylesheet to validate
        /// </param>
        /// <returns> a <code>CleanResuts</code> object containing the results of the
        /// scan
        /// </returns>
        /// <throws>  ScanException </throws>
        /// <summary>             if an error occurs during scanning
        /// </summary>
        public virtual CleanResults scanStyleSheet(string taintedCss, int sizeLimit)
        {
            // TODO: Do something about sizeLimit
            return doScan(taintedCss, isInlineCss: false);
        }

        /// <summary> Scans the contents of an inline style declaration (ex. in the style
        /// attribute of an HTML tag) and validates the style sheet according to this
        /// <code>CssScanner</code>'s policy file.
        /// 
        /// </summary>
        /// <param name="taintedCss">a <code>String</code> containing the contents of the CSS
        /// stylesheet to validate
        /// </param>
        /// <param name="tagName">the name of the tag for which this inline style was declared
        /// </param>
        /// <returns> a <code>CleanResuts</code> object containing the results of the
        /// scan
        /// </returns>
        /// <throws>  ScanException </throws>
        /// <summary>             if an error occurs during scanning
        /// </summary>

        public virtual CleanResults scanInlineStyle(string taintedCss, string tagName, int sizeLimit)
        {
            // TODO: Do something about tagName (probably delete it later)
            return doScan(taintedCss, isInlineCss: true);
        }

        private CleanResults doScan(string taintedCss, bool isInlineCss)
        {
            DateTime startOfScan = new DateTime();
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

                string result = scanStyleSheet(styleSheet, errorMessages);
                cleanStylesheet = isInlineCss ? cleanDummyWrapper(result) : result;
            }
            catch (ParseException)
            {
                throw;
            }
            catch (Exception exception)
            {
                throw new ScanException("An error occured while scanning css", exception);
            }

            return new CleanResults(startOfScan, new DateTime(), cleanStylesheet, null, errorMessages);
        }

        private string cleanDummyWrapper(string result)
        {
            if (result.StartsWith(DUMMY_SELECTOR_BEGIN))
            {
                result = result.Replace(DUMMY_SELECTOR_BEGIN, string.Empty);

                if (result.EndsWith("}"))
                {
                    result = result.Remove(result.Length - 1);
                }
            }
            return string.IsNullOrWhiteSpace(result) ? string.Empty : result;
        }

        private string scanStyleSheet(ICssStyleSheet styleSheet, List<string> errorMessages)
        {
            for (var i = 0; i < styleSheet.Rules.Length;)
            {
                ICssRule rule = styleSheet.Rules[i];
                if (!scanStyleRule(rule, errorMessages))
                    styleSheet.RemoveAt(i);
                else
                    i++;
            }

            var stringWriter = new StringWriter();
            styleSheet.ToCss(stringWriter, new CssStyleFormatter());
            return stringWriter.GetStringBuilder().ToString();
        }

        private bool scanStyleRule(ICssRule rule, List<string> errorMessages)
        {
            if (rule is ICssStyleRule styleRule)
            {
                scanStyleDeclaration(styleRule.Style, errorMessages);
            }
            else if (rule is ICssGroupingRule groupingRule)
            {
                foreach (ICssRule childRule in groupingRule.Rules)
                {
                    scanStyleRule(childRule, errorMessages);
                }
            }
            else if (rule is ICssPageRule pageRule)
            {
                scanStyleDeclaration(pageRule.Style, errorMessages);
            }
            else if (rule is ICssKeyframesRule keyFramesRule)
            {
                foreach (ICssKeyframeRule childRule in keyFramesRule.Rules.OfType<ICssKeyframeRule>().ToList())
                {
                    scanStyleRule(childRule, errorMessages);
                }
            }
            else if (rule is ICssKeyframeRule keyFrameRule)
            {
                scanStyleDeclaration(keyFrameRule.Style, errorMessages);
            }
            else if (rule is ICssImportRule importRule)
            {
                //Dont allow import rules for now
                return false;
            }

            return true;
        }

        private void scanStyleDeclaration(ICssStyleDeclaration styles, List<string> errorMessages)
        {
            var removingProperties = new List<Tuple<ICssProperty, string>>();

            var cssUrlTest = new Regex(@"[Uu][Rr\u0280][Ll\u029F]\s*\(\s*(['""]?)\s*([^'"")\s]+)\s*(['""]?)\s*", RegexOptions.Compiled);
            var dangerousCssExpressionTest = new Regex(@"[eE\uFF25\uFF45][xX\uFF38\uFF58][pP\uFF30\uFF50][rR\u0280\uFF32\uFF52][eE\uFF25\uFF45][sS\uFF33\uFF53]{2}[iI\u026A\uFF29\uFF49][oO\uFF2F\uFF4F][nN\u0274\uFF2E\uFF4E]", RegexOptions.Compiled);

            foreach (ICssProperty cssProperty in styles)
            {
                string key = decodeCss(cssProperty.Name);
                string value = decodeCss(cssProperty.Value);

                Property allowedCssProperty = policy.GetPropertyByName(key);

                if (allowedCssProperty == null)
                {
                    removingProperties.Add(new Tuple<ICssProperty, string>(cssProperty, $"Css property \"{key}\" is not allowed"));
                    continue;
                }

                if (dangerousCssExpressionTest.IsMatch(value))
                {
                    removingProperties.Add(new Tuple<ICssProperty, string>(cssProperty, $"\"{value}\" is invalid css expression"));
                    continue;
                }

                validateValue(allowedCssProperty, cssProperty, value, removingProperties);

                MatchCollection urls = cssUrlTest.Matches(value);

                if (urls.Count > 0)
                {
                    var schemeRegex = new Regex(@"^\s*([^\/#]*?)(?:\:|&#0*58|&#x0*3a)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

                    if (!urls.Cast<Match>().All(u => schemeRegex.IsMatch(u.Value)))
                    {
                        removingProperties.Add(new Tuple<ICssProperty, string>(cssProperty, "Illegal url detected."));
                    }
                }
            }

            foreach (Tuple<ICssProperty, string> style in removingProperties)
            {
                styles.RemoveProperty(style.Item1.Name);
                errorMessages.Add(style.Item2);
            }
        }

        private void validateValue(Property allowedCssProperty, ICssProperty cssProperty, string value, List<Tuple<ICssProperty, string>> removeStyles)
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
                    validateValue(shorthand, cssProperty, value, removeStyles);
                }
            }
        }

        private static string decodeCss(string css)
        {
            var cssComments = new Regex(@"/\*.*?\*/", RegexOptions.Compiled);
            var cssUnicodeEscapes = new Regex(@"\\([0-9a-fA-F]{1,6})\s?|\\([^\r\n\f0-9a-fA-F'""{};:()#*])", RegexOptions.Compiled);

            string r = cssUnicodeEscapes.Replace(css, m =>
            {
                if (m.Groups[1].Success)
                {
                    return ((char)int.Parse(m.Groups[1].Value, NumberStyles.HexNumber)).ToString();
                }
                string t = m.Groups[2].Value;
                return t == "\\" ? @"\\" : t;
            });

            r = cssComments.Replace(r, m => "");

            return r;
        }

        //        /// <summary> Test method to demonstrate CSS scanning.
        //        /// 
        //        /// </summary>
        //        /// <deprecated>
        //        /// </deprecated>
        //        /// <param name="args">unused
        //        /// </param>
        //        /// <throws>  Exception </throws>
        //        /// <summary>             if any error occurs
        //        /// </summary>
        //        [STAThread]
        //        public static void  Main(System.String[] args)
        //        {
        //            Policy policy = Policy.getInstance();
        //            CssScanner scanner = new CssScanner(policy);

        //            CleanResults results = null;

        //            results = scanner.scanStyleSheet(".test, demo, #id {position:absolute;border: thick solid red;} ");

        //            // Test case for live CSS docs. Just change URL to a live CSS on the
        //            // internet. Note this is test code and does not handle IO errors
        //            //		StringBuilder sb = new StringBuilder();
        //            //		BufferedReader reader = new BufferedReader(new InputStreamReader(
        //            //				new URL("http://www.owasp.org/skins/monobook/main.css")
        //            //						.openStream()));
        //            //		String line = null;
        //            //		while ((line = reader.readLine()) != null) {
        //            //			sb.append(line);
        //            //			sb.append("\n");
        //            //		}
        //            //		results = scanner.scanStyleSheet(sb.toString());

        //            System.Console.Out.WriteLine("Cleaned result:");
        //            System.Console.Out.WriteLine(results.CleanHTML);
        //            System.Console.Out.WriteLine("--");
        //            System.Console.Out.WriteLine("Error messages");
        //            //UPGRADE_TODO: Method 'java.io.PrintStream.println' was converted to 'System.Console.Out.WriteLine' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioPrintStreamprintln_javalangObject'"
        //            System.Console.Out.WriteLine(SupportClass.CollectionToString(results.ErrorMessages));
        //        }
    }
}