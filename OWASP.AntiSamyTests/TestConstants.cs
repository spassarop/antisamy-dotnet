/*
 * Copyright (c) 2020, Sebastián Passaro
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

namespace AntiSamyTests
{
    public static class TestConstants
    {
        public static readonly string DEFAULT_POLICY_PATH = "Resources/antisamy.xml";
        public static readonly string ANYTHINGGOES_POLICY_PATH = "Resources/antisamy-anythinggoes.xml";
        public static readonly string EBAY_POLICY_PATH = "Resources/antisamy-ebay.xml";
        public static readonly string MYSPACE_POLICY_PATH = "Resources/antisamy-myspace.xml";
        public static readonly string SLASHDOT_POLICY_PATH = "Resources/antisamy-slashdot.xml";
        public static readonly string TEST_POLICY_PATH = "Resources/antisamy-test.xml";
        public static readonly string TINYMCE_POLICY_PATH = "Resources/antisamy-tinymce.xml";
        public static readonly string POLICY_HEADER = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n" +
                                         "<anti-samy-rules xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
                                         "xsi:noNamespaceSchemaLocation=\"antisamy.xsd\">\n";
        public static readonly string POLICY_DIRECTIVES = "<directives>\n</directives>\n";
        public static readonly string POLICY_COMMON_ATTRIBUTES = "<common-attributes>\n</common-attributes>\n";
        public static readonly string POLICY_GLOBAL_TAG_ATTRIBUTES = "<global-tag-attributes>\n</global-tag-attributes>\n";
        public static readonly string POLICY_DYNAMIC_TAG_ATTRIBUTES = "<dynamic-tag-attributes>\n</dynamic-tag-attributes>\n";
        public static readonly string POLICY_TAG_RULES = "<tag-rules>\n</tag-rules>";
        public static readonly string POLICY_CSS_RULES = "<css-rules>\n</css-rules>\n";
        public static readonly string POLICY_COMMON_REGEXPS = "<common-regexps>\n</common-regexps>";
        public static readonly string POLICY_FOOTER = "</anti-samy-rules>";
    }
}
