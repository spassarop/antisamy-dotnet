/*
 * Copyright (c) 2007-2022, Arshan Dabirsiaghi, Jason Li, Kristian Rosenvold, Sebastián Passaro
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
using OWASP.AntiSamy.Html.Model;
using Attribute = OWASP.AntiSamy.Html.Model.Attribute;
using Tag = OWASP.AntiSamy.Html.Model.Tag;

namespace OWASP.AntiSamy.Html
{
    /// <summary>This class has all the collections used to store the parsed policy.</summary>
    public class ParseContext
    {
        internal Dictionary<string, string> commonRegularExpressions = new Dictionary<string, string>();
        internal Dictionary<string, Attribute> commonAttributes = new Dictionary<string, Attribute>();
        internal Dictionary<string, Tag> tagRules = new Dictionary<string, Tag>();
        internal Dictionary<string, Property> cssRules = new Dictionary<string, Property>();
        internal Dictionary<string, string> directives = new Dictionary<string, string>();
        internal Dictionary<string, Attribute> globalAttributes = new Dictionary<string, Attribute>();
        internal Dictionary<string, Attribute> dynamicAttributes = new Dictionary<string, Attribute>();
        internal List<string> allowedEmptyTags = new List<string>();

        internal void ResetParametersWhereLastConfigurationWins()
        {
            allowedEmptyTags.Clear();
        }
    }
}
