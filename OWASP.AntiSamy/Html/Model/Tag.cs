/*
 * Copyright (c) 2008-2023, Jerry Hoff, Sebastián Passaro
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
using System.Text;
using OWASP.AntiSamy.Html.Scan;
using OWASP.AntiSamy.Html.Util;

namespace OWASP.AntiSamy.Html.Model
{
    /// <summary> A model for HTML "tags" and the rules dictating their validation/filtration. Also contains 
    /// information about their allowed attributes. There is also some experimental (unused) code in here for
    /// generating a valid regular expression according to a policy file on a per-tag basis.</summary>
    public class Tag
    {
        internal string Action { get; set; }
        internal string Name { get; set; }
        internal Dictionary<string, Attribute> AllowedAttributes { get; set; } = new Dictionary<string, Attribute>();

        /// <summary> Constructor.</summary>
        /// <param name="name">The name of the tag, such as "b" for &lt;b&gt; tags.</param>
        internal Tag(string name) => Name = name;

        /// <summary> Constructor.</summary>
        /// <param name="name">The name of the tag, such as "b" for &lt;b&gt; tags.</param>
        /// <param name="action">The action to take with the tag, like <c>"remove"</c>.</param>
        /// <param name="allowedAttributes">The allowed attributes dictionary for the tag.</param>
        internal Tag(string name, string action, Dictionary<string, Attribute> allowedAttributes) 
        {
            Name = name;
            Action = action;
            AllowedAttributes = allowedAttributes;
        }

        /// <summary> Adds a fully-built <see cref="Attribute"/> to the list of attributes allowed for this tag.</summary>
        /// <param name="attribute">The <see cref="Attribute"/> to add to the list of allowed attributes.</param>
        internal void AddAttribute(Attribute attribute)
        {
            AllowedAttributes[attribute.Name] = attribute;
        }

        /// <summary> Returns an <see cref="Attribute"/> associated with a lookup name.</summary>
        /// <param name="name">The name of the allowed attribute by name.</param>
        /// <returns> The <see cref="Attribute"/> object associated with the name.</returns>
        internal Attribute GetAttributeByName(string name) => AllowedAttributes.GetValueOrTypeDefault(name);

        internal string GetRegularExpression()
        {
            // For such tags as <b>, <i>, <u>
            if (!AllowedAttributes.Any())
            {
                return $"^<{Name}>$";
            }

            var regExp = new StringBuilder($"<{Constants.ANY_NORMAL_WHITESPACES}{Name}{Constants.OPEN_TAG_ATTRIBUTES}");

            List<Attribute> attributeList = AllowedAttributes.Values.OrderBy(a => a.Name).ToList();
            for (int i = 0; i < attributeList.Count; i++)
            {
                regExp.Append(attributeList[i].MatcherRegEx());
                if (i < attributeList.Count - 1)
                {
                    regExp.Append(Constants.ATTRIBUTE_DIVIDER);
                }
            }

            regExp.Append($"{Constants.CLOSE_TAG_ATTRIBUTES}{Constants.ANY_NORMAL_WHITESPACES}>");

            return regExp.ToString();
        }

        internal static string EscapeRegularExpressionCharacters(string allowedValue)
        {
            string toReturn = allowedValue;
            if (toReturn == null)
            {
                return null;
            }
            for (int i = 0; i < Constants.REGEXP_CHARACTERS.Length; i++)
            {
                toReturn = toReturn.Replace("\\" + System.Convert.ToString(Constants.REGEXP_CHARACTERS[i]), "\\" + Constants.REGEXP_CHARACTERS[i]);
            }
            return toReturn;
        }

        /// <summary> Creates a new Tag based on this one, but changing the action.</summary>
        /// <param name="action">The new action for the new <see cref="Tag"/>.</param>
        /// <returns>The duplicated <see cref="Tag"/> with the provided action.</returns>
        internal Tag MutateAction(string action) => new Tag(Name, action, AllowedAttributes);
    }
}
