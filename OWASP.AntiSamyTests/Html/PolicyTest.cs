/*
* Copyright (c) 2009-2020, Arshan Dabirsiaghi
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
        private static string[] AllPolicyFilePaths = { 
            TestConstants.DEFAULT_POLICY_PATH, TestConstants.ANYTHINGGOES_POLICY_PATH, TestConstants.EBAY_POLICY_PATH, 
            TestConstants.MYSPACE_POLICY_PATH, TestConstants.SLASHDOT_POLICY_PATH, TestConstants.TEST_POLICY_PATH, 
            TestConstants.TINYMCE_POLICY_PATH 
        };

        private string AssembleFile(string allowedEmptyTagsSection)
        {
            return TestConstants.POLICY_HEADER + TestConstants.POLICY_DIRECTIVES + TestConstants.POLICY_COMMON_REGEXPS
                + TestConstants.POLICY_COMMON_ATTRIBUTES + TestConstants.POLICY_GLOBAL_TAG_ATTRIBUTES
                + TestConstants.POLICY_DYNAMIC_TAG_ATTRIBUTES + TestConstants.POLICY_TAG_RULES
                + TestConstants.POLICY_CSS_RULES + allowedEmptyTagsSection + TestConstants.POLICY_FOOTER;
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

            var policy = Policy.GetInstance(new MemoryStream(Encoding.UTF8.GetBytes(policyFile)));

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

            var policy = Policy.GetInstance(new MemoryStream(Encoding.UTF8.GetBytes(policyFile)));
            policy.GetAllowedEmptyTags().Size().Should().Be(0);
        }

        [Test]
        public void TestGetAllowedEmptyTagsWithEmptySection()
        {
            string policyFile = AssembleFile("<allowed-empty-tags>\n" +
                                         "</allowed-empty-tags>\n");

            var policy = Policy.GetInstance(new MemoryStream(Encoding.UTF8.GetBytes(policyFile)));
            policy.GetAllowedEmptyTags().Size().Should().Be(0);
        }

        [Test]
        public void TestGetAllowedEmptyTagsWithNoSection()
        {
            string policyFile = AssembleFile(string.Empty);

            var policy = Policy.GetInstance(new MemoryStream(Encoding.UTF8.GetBytes(policyFile)));
            policy.GetAllowedEmptyTags().Size().Should().Be(Constants.DEFAULT_ALLOWED_EMPTY_TAGS.Count);
        }

        [Test]
        public void TestCreateFromFilename([ValueSource("AllPolicyFilePaths")] string policyFile)
        {
            Policy policy = null;
            try
            {
                policy = Policy.GetInstance(policyFile);
            }
            catch
            {
                // To comply with try/catch
            }

            policy.Should().NotBeNull();
        }

        [Test]
        public void TestCreateFromFileInfo()
        {
            Policy policy = null;
            try
            {
                policy = Policy.GetInstance(new FileInfo(TestConstants.DEFAULT_POLICY_PATH));
            }
            catch
            {
                // To comply with try/catch
            }

            policy.Should().NotBeNull();
        }
    }
}
