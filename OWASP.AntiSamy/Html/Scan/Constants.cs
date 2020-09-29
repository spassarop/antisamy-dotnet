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

namespace OWASP.AntiSamy.Html.Scan
{
    public static class Constants
    {
        public static readonly List<string> DEFAULT_ALLOWED_EMPTY_TAGS = new List<string> {
            "br", "hr", "a", "img", "link", "iframe", "script", "object", "applet", "frame", 
            "base", "param", "meta", "input", "textarea", "embed", "basefont", "col"
        };

        // For Tag regular expression building
        public static readonly string REGEXP_CHARACTERS = "\\(){}.*?$^-+";
        public static readonly string ANY_NORMAL_WHITESPACES = "(\\s)*";
        public static readonly string OPEN_ATTRIBUTE = "(";
        public static readonly string ATTRIBUTE_DIVIDER = "|";
        public static readonly string CLOSE_ATTRIBUTE = ")";
        public static readonly string OPEN_TAG_ATTRIBUTES = ANY_NORMAL_WHITESPACES + OPEN_ATTRIBUTE;
        public static readonly string CLOSE_TAG_ATTRIBUTES = CLOSE_ATTRIBUTE + "*";
    }
}
