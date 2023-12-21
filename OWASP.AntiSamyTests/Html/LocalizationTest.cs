/*
 * Copyright (c) 2023, Sebastián Passaro
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
using System.Linq;
using FluentAssertions;
using NUnit.Framework;
using OWASP.AntiSamy.Html;
using Constants = OWASP.AntiSamy.Html.Scan.Constants;

namespace AntiSamyTests
{
    /// <summary>This class is made only to test that messages on 
    /// all supported cultures at least return a message.</summary>
    [TestFixture]
    public class LocalizationTest
    {
        private AntiSamy antisamy;
        private Policy policy;

        [SetUp]
        public void SetUp()
        {
            antisamy = new AntiSamy();
            policy = Policy.GetInstance(TestConstants.DEFAULT_POLICY_PATH);
        }

        [Test]
        public void TestMessageInSupportedCulture()
        {
            foreach (string cultureName in Constants.SUPPORTED_LANGUAGES.Union(new List<string> { "en-US", "es-UY" }))
            {
                string message = null;

                try
                {
                    policy.Should().NotBeNull();
                    antisamy.SetCulture(cultureName);
                    CleanResults results = antisamy.Scan("<unknowntag>", policy);
                    results.GetNumberOfErrors().Should().Be(1);
                    message = results.GetErrorMessages().First();
                }
                catch
                {
                    // To comply with try/catch
                }

                message.Should().NotBeNull(because: $"\"{cultureName}\" should be a valid culture and have an associated message.");
            }
        }

        [Test]
        public void TestInvalidAndNotSupportedCultures()
        {
            var invalidCultures = new List<string> { "EN", "en-USS", "en-us", "<bad>" };
            var notSupportedCultures = new List<string> { "mt", "mt-MT", "hh" };

            foreach (string cultureName in invalidCultures.Union(notSupportedCultures))
            {
                string message = null;

                try
                {
                    antisamy.SetCulture(cultureName);
                    message = antisamy.Scan("<unknowntag>", policy).GetErrorMessages().First();
                }
                catch
                {
                    // To comply with try/catch
                }

                message.Should().BeNull(because: $"\"{cultureName}\" should be either invalid or not supported.");
            }
        }
    }
}
