/*
 * Copyright (c) 2008-2020, Jerry Hoff, Sebasti�n Passaro
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

namespace OWASP.AntiSamy.Html.Scan
{
    internal static class Constants
    {
        public static readonly List<string> DEFAULT_ALLOWED_EMPTY_TAGS = new List<string> {
            "br", "hr", "a", "img", "link", "iframe", "script", "object", "applet", "frame", 
            "base", "param", "meta", "input", "textarea", "embed", "basefont", "col"
        };

        public static readonly List<string> DEFAULT_REQUIRE_CLOSING_TAGS = new List<string> {
            "iframe", "script", "link"
        };

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
        public static readonly string ENTITY_ENCODE_INERNATIONAL_CHARS = "entityEncodeIntlChars";
        public static readonly string ALLOW_DYNAMIC_ATTRIBUTES = "allowDynamicAttributes";
        public static readonly int DEFAULT_MAX_INPUT_SIZE = 100_000;
        public static readonly int MAX_NESTED_TAGS = 1000;

        public static readonly string ACTION_FILTER = "filter";
        public static readonly string ACTION_VALIDATE = "validate";
        public static readonly string ACTION_TRUNCATE = "truncate";
        public static readonly string ACTION_ENCODE = "encode";

        public static readonly string DEFAULT_POLICY_URI = "Resources/antisamy.xml";
        public static readonly string DEFAULT_POLICY_RESOURCE_KEY = "DEFAULT_ANTISAMY_POLICY_XML";
        public static readonly string DEFAULT_POLICY_SCHEMA_RESOURCE_KEY = "DEFAULT_ANTISAMY_POLICY_XSD";
        public static readonly string DEFAULT_ONINVALID = "removeAttribute";

        // Error message keys
        public static readonly string ERROR_CULTURE_NOTSUPPORTED = "Error.Culture.NotSupported";
        public static readonly string ERROR_SIZE_TOOLARGE = "Error.Size.TooLarge";
        public static readonly string ERROR_COMMENT_REMOVED = "Error.Comment.Removed";
        public static readonly string ERROR_TAG_NOT_IN_POLICY = "Error.Tag.NotFound";
        public static readonly string ERROR_TAG_DISALLOWED = "Error.Tag.Removed";
        public static readonly string ERROR_TAG_FILTERED = "Error.Tag.Filtered";
        public static readonly string ERROR_TAG_ENCODED = "Error.Tag.Encoded";
        public static readonly string ERROR_TAG_EMPTY = "Error.Tag.Empty";
        public static readonly string ERROR_CDATA_FOUND = "Error.CData.Found";
        public static readonly string ERROR_PI_FOUND = "Error.Pi.Found";
        public static readonly string ERROR_ATTRIBUTE_NOT_IN_POLICY = "Error.Attribute.NotFound";
        public static readonly string ERROR_ATTRIBUTE_INVALID = "Error.Attribute.Invalid";
        public static readonly string ERROR_ATTRIBUTE_CAUSE_FILTER = "Error.Attribute.Invalid.Filtered";
        public static readonly string ERROR_ATTRIBUTE_CAUSE_ENCODE = "Error.Attribute.Invalid.Encoded";
        public static readonly string ERROR_ATTRIBUTE_INVALID_REMOVED = "Error.Attribute.Invalid.Removed";
        public static readonly string ERROR_CSS_TAG_MALFORMED = "Error.Css.Tag.Malformed";
        public static readonly string ERROR_CSS_ATTRIBUTE_MALFORMED = "Error.Css.Attribute.Malformed";
        public static readonly string ERROR_CSS_IMPORT_DISABLED = "Error.Css.Import.Disabled";
        public static readonly string ERROR_CSS_IMPORT_EXCEEDED = "Error.Css.Import.Exceeded";
        public static readonly string ERROR_CSS_IMPORT_FAILURE = "Error.Css.Import.Failure";
        public static readonly string ERROR_CSS_IMPORT_TOOLARGE = "Error.Css.Import.TooLarge";
        public static readonly string ERROR_CSS_IMPORT_URL_INVALID = "Error.Css.Import.Url.Invalid";
        public static readonly string ERROR_CSS_STYLESHEET_RELATIVE = "Error.Css.Stylesheet.Relative";
        public static readonly string ERROR_CSS_TAG_RELATIVE = "Error.Css.Tag.Relative";
        public static readonly string ERROR_CSS_STYLESHEET_RULE_NOTFOUND = "Error.Css.Stylesheet.Rule.NotFound";
        public static readonly string ERROR_CSS_TAG_RULE_NOTFOUND = "Error.Css.Tag.Rule.NotFound";
        public static readonly string ERROR_CSS_STYLESHEET_SELECTOR_NOTFOUND = "Error.Css.Stylesheet.Selector.NotFound";
        public static readonly string ERROR_CSS_TAG_SELECTOR_NOTFOUND = "Error.Css.Tag.Selector.NotFound";
        public static readonly string ERROR_CSS_STYLESHEET_SELECTOR_DISALLOWED = "Error.Css.Stylesheet.Selector.Disallowed";
        public static readonly string ERROR_CSS_TAG_SELECTOR_DISALLOWED = "Error.Css.Tag.Selector.Disallowed";
        public static readonly string ERROR_CSS_STYLESHEET_PROPERTY_INVALID = "Error.Css.Stylesheet.Property.Invalid";
        public static readonly string ERROR_CSS_TAG_PROPERTY_INVALID = "Error.Css.Tag.Property.Invalid";
        public static readonly string ERROR_CSS_RULE_NOTALLOWED = "Error.Css.Rule.NotAllowed";
        public static readonly string ERROR_CSS_PROPERTY_VALUE_INVALID = "Error.Css.Property.Value.Invalid";
        public static readonly string ERROR_CSS_PROPERTY_SINGLEVALUE_INVALID = "Error.Css.Property.SingleValue.Invalid";

        // Supported languages
        public static readonly List<string> SUPPORTED_LANGUAGES = new List<string> {
            "de-DE", "en-AU", "en-CA", "en-GB", "en-US", "es-MX", 
            "it-IT", "no-NB", "pt-BR", "pt-PT", "ru-RU", "zh-CN"
        };
    }
}
