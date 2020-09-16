/*
* Copyright (c) 2009-2020, Jerry Hoff
* 
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
* 
* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of OWASP nor the names of its contributors  may be used to endorse or promote products derived from this software without specific prior written permission.
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
using OWASP.AntiSamy.Html;
using NUnit.Framework;
using System.Text.RegularExpressions;

namespace AntiSamyTests
{
    [TestFixture]
    public class AntiSamyTest
    {
        AntiSamy antisamy = new AntiSamy();
        Policy policy = null;
        string filename = "Resources/antisamy.xml";

        [SetUp]
        public void SetUp() => policy = Policy.GetInstance(filename);

        [TearDown]
        public void TearDown()
        {
        }

        /*
         * Test basic XSS cases. 
         */
        [Test]
        public void TestScriptAttacks()
        {
            try
            {
                Assert.IsTrue(!antisamy.Scan("test<script>alert(document.cookie)</script>", policy).GetCleanHTML().Contains("script"));
                Assert.IsTrue(!antisamy.Scan("<<<><<script src=http://fake-evil.ru/test.js>", policy).GetCleanHTML().Contains("<script"));
                Assert.IsTrue(!antisamy.Scan("<script<script src=http://fake-evil.ru/test.js>>", policy).GetCleanHTML().Contains("<script"));
                Assert.IsTrue(!antisamy.Scan("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).GetCleanHTML().Contains("<script"));
                Assert.IsTrue(!antisamy.Scan("<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>", policy).GetCleanHTML().Contains("onload"));
                Assert.IsTrue(!antisamy.Scan("<BODY ONLOAD=alert('XSS')>", policy).GetCleanHTML().Contains("alert"));
                Assert.IsTrue(!antisamy.Scan("<iframe src=http://ha.ckers.org/scriptlet.html <", policy).GetCleanHTML().Contains("<iframe"));
                Assert.IsTrue(!antisamy.Scan("<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">", policy).GetCleanHTML().Contains("src"));
            }
            catch (Exception e)
            {
                Assert.Fail($"Caught exception in TestScriptAttack(): {e.Message}");
            }
        }

        [Test]
        public void TestImgAttacks()
        {
            try
            {
                Assert.IsTrue(antisamy.Scan("<img src='http://www.myspace.com/img.gif'>", policy).GetCleanHTML().Contains("<img"));
                Assert.IsTrue(!antisamy.Scan("<img src=javascript:alert(document.cookie)>", policy).GetCleanHTML().Contains("<img"));
                Assert.IsTrue(!antisamy.Scan("<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", policy).GetCleanHTML().Contains("<img"));       
                Assert.IsTrue(antisamy.Scan("<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>", policy).GetCleanHTML().Contains("&amp;"));
                Assert.IsTrue(antisamy.Scan("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>", policy).GetCleanHTML().Contains("&amp;"));
                Assert.IsTrue(!antisamy.Scan("<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">", policy).GetCleanHTML().Contains("alert"));
                Assert.IsTrue(!antisamy.Scan("<IMG SRC=\"javascript:alert('XSS')\"", policy).GetCleanHTML().Contains("javascript"));
                Assert.IsTrue(!antisamy.Scan("<IMG LOWSRC=\"javascript:alert('XSS')\">", policy).GetCleanHTML().Contains("javascript"));
                Assert.IsTrue(!antisamy.Scan("<BGSOUND SRC=\"javascript:alert('XSS');\">", policy).GetCleanHTML().Contains("javascript"));
            }
            catch (Exception e)
            {
                Assert.Fail($"Caught exception in TestImgAttacks(): {e.Message}");
            }
        }

        [Test]
        public void TestHrefAttacks()
        {
            try
            {
                Assert.IsTrue(!antisamy.Scan("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">", policy).GetCleanHTML().Contains("href"));
                Assert.IsTrue(!antisamy.Scan("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">", policy).GetCleanHTML().Contains("href"));
                Assert.IsTrue(!antisamy.Scan("<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>", policy).GetCleanHTML().Contains("ha.ckers.org"));
                Assert.IsTrue(!antisamy.Scan("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", policy).GetCleanHTML().Contains("ha.ckers.org"));
                Assert.IsTrue(!antisamy.Scan("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", policy).GetCleanHTML().Contains("xss.htc"));
                Assert.IsTrue(!antisamy.Scan("<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS", policy).GetCleanHTML().Contains("javascript"));
                Assert.IsTrue(!antisamy.Scan("<IMG SRC='vbscript:msgbox(\"XSS\")'>", policy).GetCleanHTML().Contains("vbscript"));
                Assert.IsTrue(!antisamy.Scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">", policy).GetCleanHTML().Contains("<meta"));
                Assert.IsTrue(!antisamy.Scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">", policy).GetCleanHTML().Contains("<meta"));
                Assert.IsTrue(!antisamy.Scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">", policy).GetCleanHTML().Contains("<meta"));
                Assert.IsTrue(!antisamy.Scan("<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>", policy).GetCleanHTML().Contains("iframe"));
                Assert.IsTrue(!antisamy.Scan("<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>", policy).GetCleanHTML().Contains("javascript"));
                Assert.IsTrue(!antisamy.Scan("<TABLE BACKGROUND=\"javascript:alert('XSS')\">", policy).GetCleanHTML().Contains("background"));
                Assert.IsTrue(!antisamy.Scan("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">", policy).GetCleanHTML().Contains("background"));
                Assert.IsTrue(!antisamy.Scan("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">", policy).GetCleanHTML().Contains("javascript"));
                Assert.IsTrue(!antisamy.Scan("<DIV STYLE=\"width: expression(alert('XSS'));\">", policy).GetCleanHTML().Contains("alert"));
                Assert.IsTrue(!antisamy.Scan("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">", policy).GetCleanHTML().Contains("alert"));
                Assert.IsTrue(!antisamy.Scan("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>", policy).GetCleanHTML().Contains("ript:alert"));
                Assert.IsTrue(!antisamy.Scan("<BASE HREF=\"javascript:alert('XSS');//\">", policy).GetCleanHTML().Contains("javascript"));
                Assert.IsTrue(!antisamy.Scan("<BaSe hReF=\"http://arbitrary.com/\">", policy).GetCleanHTML().Contains("<base"));
                Assert.IsTrue(!antisamy.Scan("<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>", policy).GetCleanHTML().Contains("<object"));
                Assert.IsTrue(!antisamy.Scan("<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>", policy).GetCleanHTML().Contains("<object"));
                Assert.IsTrue(!antisamy.Scan("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>", policy).GetCleanHTML().Contains("<embed"));
                Assert.IsTrue(!antisamy.Scan("<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>", policy).GetCleanHTML().Contains("<embed"));
                Assert.IsTrue(!antisamy.Scan("<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).GetCleanHTML().Contains("<script"));
                Assert.IsTrue(!antisamy.Scan("<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).GetCleanHTML().Contains("<script"));
                Assert.IsTrue(!antisamy.Scan("<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).GetCleanHTML().Contains("<script"));
                Assert.IsTrue(!antisamy.Scan("<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).GetCleanHTML().Contains("<script"));
                Assert.IsTrue(!antisamy.Scan("<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).GetCleanHTML().Contains("script"));
                Assert.IsTrue(!antisamy.Scan("<SCRIPT SRC=http://ha.ckers.org/xss.js", policy).GetCleanHTML().Contains("<script"));
                Assert.IsTrue(!antisamy.Scan("<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>", policy).GetCleanHTML().Contains("&amp;"));
                Assert.IsTrue(!antisamy.Scan("<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>", policy).GetCleanHTML().Contains("aim.exe"));
                Assert.IsTrue(!antisamy.Scan("<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->", policy).GetCleanHTML().Contains("javascript"));
                Assert.IsTrue(!antisamy.Scan("<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">", policy).GetCleanHTML().Contains("document"));
            }
            catch (Exception e)
            {
                Assert.Fail($"Caught exception in TestHrefAttacks(): {e.Message}");
            }
        }

        /*
         * Test CSS protections. 
         */
        [Test]
        public void TestCssAttacks()
        {
            try
            {
                Assert.IsTrue(!antisamy.Scan("<div style=\"position:absolute\">", policy).GetCleanHTML().Contains("position"));
                Assert.IsTrue(!antisamy.Scan("<style>b { position:absolute }</style>", policy).GetCleanHTML().Contains("position"));
                Assert.IsTrue(!antisamy.Scan("<div style=\"z-index:25\">", policy).GetCleanHTML().Contains("position"));
                Assert.IsTrue(!antisamy.Scan("<style>z-index:25</style>", policy).GetCleanHTML().Contains("position"));
            }
            catch (Exception e)
            {
                Assert.Fail($"Caught exception in TestCssAttacks(): {e.Message}");
            }
        }

        /*
         * Tests issues #12 and #36 from nahsra/antisamy.
         */
        [Test]
        public void TestEmptyTags()
        {
            string html = antisamy.Scan("<br ><strong></strong><a>hello world</a><b /><i/><hr>", policy).GetCleanHTML();
                
            var regex = new Regex(".*<strong(\\s*)/>.*");
            Assert.IsFalse(regex.IsMatch(html));

            regex = new Regex(".*<b(\\s*)/>.*");
            Assert.IsFalse(regex.IsMatch(html));

            regex = new Regex(".*<i(\\s*)/>.*");
            Assert.IsFalse(regex.IsMatch(html));

            Assert.IsTrue(html.Contains("<hr />") || html.Contains("<hr/>"));
        }

        /*
         * Tests issues #20 from nahsra/antisamy.
         */
        [Test]
        public void TestMisplacedTag()
        {
            Assert.IsFalse(antisamy.Scan("<b><i>Some Text</b></i>", policy).GetCleanHTML().Contains("<i />"));
        }

        /*
         * Tests issues #25 from nahsra/antisamy.
         */
        [Test]
        public void TestMarginRemovalFromInlineStyle()
        {
            Assert.AreEqual(
                expected: "<div style=\"\">Test</div>", 
                actual: antisamy.Scan("<div style=\"margin: -5em\">Test</div>", policy).GetCleanHTML());
        }
    }
}