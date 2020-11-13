/*
 * Copyright (c) 2013-2020, Kristian Rosenvold, Sebastián Passaro
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

using System.Collections.Generic;
using FluentAssertions;
using NUnit.Framework;
using OWASP.AntiSamy.Html.Model;

namespace AntiSamyTests
{
    [TestFixture]
    public class TagTest
    {
        private Attribute attribute1;
        private Attribute attribute2;
       
        [SetUp]
        public void SetUp()
        {
            attribute1 = new Attribute(
                name: "attr1", 
                description: "description1", 
                onInvalid: "onInvalid1", 
                allowedValues: new List<string> { "value1" }, 
                allowedRegExp: new List<string> { "abc" });

            attribute2 = new Attribute(
                name: "attr2",
                description: "description2",
                onInvalid: "onInvalid2",
                allowedValues: new List<string> { "value2" },
                allowedRegExp: new List<string> { "bbc" });
        }

        [Test]
        public void TestSimpleRegularExpression()
        {
            var tag = new Tag("attr1", "action", new Dictionary<string, Attribute> { { "a1", attribute1 } });
            tag.GetRegularExpression().Should().Be("<(\\s)*attr1(\\s)*(attr1(\\s)*=(\\s)*\"(value1|abc)\"(\\s)*)*(\\s)*>");
        }

        [Test]
        public void TestDoubleRegularExpression()
        {
            var tag = new Tag("attr1", "action", new Dictionary<string, Attribute> { { "a1", attribute1 }, { "a2", attribute2 } });
            tag.GetRegularExpression().Should().Be("<(\\s)*attr1(\\s)*(attr1(\\s)*=(\\s)*\"(value1|abc)\"(\\s)*|attr2(\\s)*=(\\s)*\"(value2|bbc)\"(\\s)*)*(\\s)*>");
        }
    }
}
