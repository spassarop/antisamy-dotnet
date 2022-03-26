/*
 * Copyright (c) 2008-2022, Kristian Rosenvold, Sebastián Passaro
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
using OWASP.AntiSamy.Html.Scan;
using Tag = OWASP.AntiSamy.Html.Model.Tag;
using Property = OWASP.AntiSamy.Html.Model.Property;

namespace OWASP.AntiSamy.Html
{
    /// <summary>
    /// Contains a bunch of optimized lookups over the regular Policy Class.For internal use only.
    /// Not part of any public api and may explode or self destruct at any given moment, preferably both.
    /// @author Kristian Rosenvold
    /// </summary>
    internal class InternalPolicy : Policy
    {
        public InternalPolicy(ParseContext parseContext) : base(parseContext)
        {
            SetProperties();
        }

        public InternalPolicy(Policy old, Dictionary<string, string> directives, Dictionary<string, Tag> tagRules, Dictionary<string, Property> cssRules)
                : base(old, directives, tagRules, cssRules)
        {
            SetProperties();
        }

        private void SetProperties()
        {
            MaxInputSize = GetIntegerDirective(Constants.MAX_INPUT_SIZE, Constants.DEFAULT_MAX_INPUT_SIZE);
            AddNofollowInAnchors = IsTrue(Constants.ANCHORS_NOFOLLOW);
            AddNoopenerAndNoreferrerInAnchors = IsTrue(Constants.ANCHORS_NOOPENER_NOREFERRER);
            ValidatesParamAsEmbed = IsTrue(Constants.VALIDATE_PARAM_AS_EMBED);
            FormatsOutput = IsTrue(Constants.FORMAT_OUTPUT);
            PreservesSpace = IsTrue(Constants.PRESERVE_SPACE);
            OmitsXmlDeclaration = IsTrue(Constants.OMIT_XML_DECLARATION);
            OmitsDoctypeDeclaration = IsTrue(Constants.OMIT_DOCTYPE_DECLARATION);
            EntityEncodesInternationalCharacters = IsTrue(Constants.ENTITY_ENCODE_INERNATIONAL_CHARS);
            UsesXhtml = IsTrue(Constants.USE_XHTML);
            string onUnknownTagActionValue = GetDirectiveByName(Constants.ON_UNKNOWN_TAG_ACTION);
            OnUnknownTagAction = string.IsNullOrEmpty(onUnknownTagActionValue) ? string.Empty : onUnknownTagActionValue.ToLowerInvariant();
            PreservesComments = IsTrue(Constants.PRESERVE_COMMENTS);
            EmbedsStyleSheets = IsTrue(Constants.EMBED_STYLESHEETS);
            AllowsDynamicAttributes = IsTrue(Constants.ALLOW_DYNAMIC_ATTRIBUTES);
            ConnectionTimeout = GetIntegerDirective(Constants.CONNECTION_TIMEOUT, Constants.DEFAULT_CONNECTION_TIMEOUT);
            MaxStyleSheetImports = GetIntegerDirective(Constants.MAX_STYLESHEET_IMPORTS, Constants.DEFAULT_MAX_STYLESHEET_IMPORTS);
        }

        private bool IsTrue(string booleanDirective)
        {
            return GetDirectiveByName(booleanDirective) == "true";
        }

        /// <summary>Returns the integer value from directive or a default value.</summary>
        public int GetIntegerDirective(string directiveName, int defaultValue)
        {
            return int.TryParse(GetDirectiveByName(directiveName), out int integer) ? integer : defaultValue;
        }
    }
}
