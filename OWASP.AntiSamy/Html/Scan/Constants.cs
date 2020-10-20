/*
* Copyright (c) 2008-2020, Jerry Hoff
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

using System.Collections.Generic;
using System.Collections.Immutable;

namespace OWASP.AntiSamy.Html.Scan
{
    internal static class Constants
    {
        public static readonly ImmutableList<string> DEFAULT_ALLOWED_EMPTY_TAGS = new List<string> {
            "br", "hr", "a", "img", "link", "iframe", "script", "object", "applet", "frame", 
            "base", "param", "meta", "input", "textarea", "embed", "basefont", "col"
        }.ToImmutableList();

        public static readonly ImmutableList<string> DEFAULT_REQUIRE_CLOSING_TAGS = new List<string> {
            "iframe", "script", "link"
        }.ToImmutableList();

        // For Tag regular expression building
        public static readonly string REGEXP_CHARACTERS = "\\(){}.*?$^-+";
        public static readonly string ANY_NORMAL_WHITESPACES = "(\\s)*";
        public static readonly string OPEN_ATTRIBUTE = "(";
        public static readonly string ATTRIBUTE_DIVIDER = "|";
        public static readonly string CLOSE_ATTRIBUTE = ")";
        public static readonly string OPEN_TAG_ATTRIBUTES = ANY_NORMAL_WHITESPACES + OPEN_ATTRIBUTE;
        public static readonly string CLOSE_TAG_ATTRIBUTES = CLOSE_ATTRIBUTE + "*";

        // Policy
        public static readonly string OMIT_XML_DECLARATION = "omitXmlDeclaration";
        public static readonly string OMIT_DOCTYPE_DECLARATION = "omitDoctypeDeclaration";
        public static readonly string USE_XHTML = "useXHTML";
        public static readonly string FORMAT_OUTPUT = "formatOutput";
        public static readonly string EMBED_STYLESHEETS = "embedStyleSheets";
        public static readonly string CONNECTION_TIMEOUT = "connectionTimeout";
        public static readonly string ANCHORS_NOFOLLOW = "nofollowAnchors";
        public static readonly string VALIDATE_PARAM_AS_EMBED = "validateParamAsEmbed";
        public static readonly string PRESERVE_SPACE = "preserveSpace";
        public static readonly string PRESERVE_COMMENTS = "preserveComments";
        public static readonly string ENTITY_ENCODE_INTL_CHARS = "entityEncodeIntlChars";
        public static readonly string ALLOW_DYNAMIC_ATTRIBUTES = "allowDynamicAttributes";
        public static readonly int DEFAULT_MAX_INPUT_SIZE = 100_000;

        public static readonly string ACTION_FILTER = "filter";
        public static readonly string ACTION_VALIDATE = "validate";
        public static readonly string ACTION_TRUNCATE = "truncate";

        public static readonly string DEFAULT_POLICY_URI = "Resources/antisamy.xml";
        public static readonly string DEFAULT_ONINVALID = "removeAttribute";
    }
}
