/*
* Copyright (c) 2009-2020, Jerry Hoff, Sebastián Passaro
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

using System.IO;
using System.Text;
using FluentAssertions;
using NUnit.Framework;
using OWASP.AntiSamy.Html;
using OWASP.AntiSamy.Html.Scan;

namespace AntiSamyTests
{
    [TestFixture]
    public class PolicyTest
    {
        private const string HEADER = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n" +
                                         "<anti-samy-rules xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
                                         "xsi:noNamespaceSchemaLocation=\"antisamy.xsd\">\n";
        private const string DIRECTIVES = "<directives>\n</directives>\n";
        private const string COMMON_ATTRIBUTES = "<common-attributes>\n</common-attributes>\n";
        private const string GLOBAL_TAG_ATTRIBUTES = "<global-tag-attributes>\n</global-tag-attributes>\n";
        private const string DYNAMIC_TAG_ATTRIBUTES = "<dynamic-tag-attributes>\n</dynamic-tag-attributes>\n";
        private const string TAG_RULES = "<tag-rules>\n</tag-rules>";
        private const string CSS_RULES = "<css-rules>\n</css-rules>\n";
        private const string COMMON_REGEXPS = "<common-regexps>\n</common-regexps>";
        private const string FOOTER = "</anti-samy-rules>";
        private Policy policy;

        private string AssembleFile(string allowedEmptyTagsSection)
        {
            return HEADER + DIRECTIVES + COMMON_REGEXPS + COMMON_ATTRIBUTES + GLOBAL_TAG_ATTRIBUTES + 
                DYNAMIC_TAG_ATTRIBUTES + TAG_RULES + CSS_RULES + allowedEmptyTagsSection + FOOTER;
        }

        [Test]
        public void TestGetAllowedEmptyTags()
        {
            string policyFile = AssembleFile("<allowed-empty-tags>\n" +
                                         "    <literal-list>\n" +
                                         "                <literal value=\"td\"/>\n" +
                                         "                <literal value=\"span\"/>\n" +
                                         "    </literal-list>\n" +
                                         "</allowed-empty-tags>\n");

            policy = Policy.GetInstance(new MemoryStream(Encoding.UTF8.GetBytes(policyFile)));

            TagMatcher actualTags = policy.GetAllowedEmptyTags();
            actualTags.Matches("td").Should().BeTrue();
            actualTags.Matches("span").Should().BeTrue();
        }

        [Test]
        public void TestGetAllowedEmptyTagsWithEmptyList()
        {
            string policyFile = AssembleFile("<allowed-empty-tags>\n" +
                                         "    <literal-list>\n" +
                                         "    </literal-list>\n" +
                                         "</allowed-empty-tags>\n");

            policy = Policy.GetInstance(new MemoryStream(Encoding.UTF8.GetBytes(policyFile)));
            policy.GetAllowedEmptyTags().Size().Should().Be(0);
        }

        [Test]
        public void TestGetAllowedEmptyTagsWithEmptySection()
        {
            string policyFile = AssembleFile("<allowed-empty-tags>\n" +
                                         "</allowed-empty-tags>\n");

            policy = Policy.GetInstance(new MemoryStream(Encoding.UTF8.GetBytes(policyFile)));
            policy.GetAllowedEmptyTags().Size().Should().Be(0);
        }

        [Test]
        public void TestGetAllowedEmptyTagsWithNoSection()
        {
            string policyFile = AssembleFile(string.Empty);

            policy = Policy.GetInstance(new MemoryStream(Encoding.UTF8.GetBytes(policyFile)));
            policy.GetAllowedEmptyTags().Size().Should().Be(Constants.DEFAULT_ALLOWED_EMPTY_TAGS.Count);
        }

        [Test]
        public void TestCreateFromFilename()
        {
            policy = null;
            try
            {
                policy = Policy.GetInstance("Resources/antisamy.xml");
            }
            catch 
            { 
            }

            policy.Should().NotBeNull();
        }

        [Test]
        public void TestCreateFromFileInfo()
        {
            policy = null;
            try
            {
                policy = Policy.GetInstance(new FileInfo("Resources/antisamy.xml"));
            }
            catch
            {
            }

            policy.Should().NotBeNull();
        }
    }
}
