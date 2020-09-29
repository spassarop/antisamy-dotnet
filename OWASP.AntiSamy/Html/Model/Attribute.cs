/*
* Copyright (c) 2008-2020, Jerry Hoff
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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using OWASP.AntiSamy.Html.Scan;

namespace OWASP.AntiSamy.Html.Model
{
    /// <summary> A model for HTML attributes and the "rules" they must follow 
    /// (either literals or regular expressions) in order to be considered valid.</summary>
    internal class Attribute : ICloneable
    {
        public List<string> AllowedRegExp { get; set; } = new List<string>();
        public List<string> AllowedValues { get; set; } = new List<string>();
        public string Name { get; set; }
        public string OnInvalid { get; set; }
        public string Description { get; set; }

        public Attribute(string name) => Name = name;
        public Attribute(string name, string description, string onInvalid, List<string> allowedRegExp, List<string> allowedValues)
        {
            Name = name;
            Description = description;
            OnInvalid = onInvalid;
            AllowedRegExp = allowedRegExp;
            AllowedValues = allowedValues;
        }

        /// <summary>Adds an allowed value for the attribute.</summary>
        /// <param name="safeValue">A legal literal value that an attribute can have, according to the policy.</param>
        public void AddAllowedValue(string safeValue) => AllowedValues.Add(safeValue);

        /// <summary>Adds an allowed value for the attribute.</summary>
        /// <param name="safeValueList">A legal literal value list that an attribute can have, according to the policy.</param>
        public void AddAllowedValueList(List<string> safeValueList) => AllowedValues.AddRange(safeValueList);

        /// <summary>Adds an allowed regular expression for the attribute.</summary>
        /// <param name="safeRegExpValue">A legal regular expression value that an attribute could have, according to the policy.</param>
        public void AddAllowedRegExp(string safeRegExpValue) => AllowedRegExp.Add(safeRegExpValue);

        /// <summary>Adds an allowed regular expression for the attribute.</summary>
        /// <param name="safeRegExpValueList">A legal regular expression value list that an attribute could have, according to the policy.</param>
        public void AddAllowedRegExpList(List<string> safeRegExpValueList) => AllowedRegExp.AddRange(safeRegExpValueList);

        /// <summary> We need to implement <see cref="ICloneable.Clone"/> to make the policy file work with common attributes and the ability
        /// to use a common-attribute with an alternative <see cref="OnInvalid"/> action.</summary>
        public object Clone() => new Attribute(Name)
        {
            Description = Description,
            OnInvalid = OnInvalid,
            AllowedValues = AllowedValues,
            AllowedRegExp = AllowedRegExp
        };

        public string MatcherRegEx()
        {
            var regExp = new StringBuilder()
                .Append(Name)
                .Append(Constants.ANY_NORMAL_WHITESPACES)
                .Append("=")
                .Append(Constants.ANY_NORMAL_WHITESPACES)
                .Append("\"")
                .Append(Constants.OPEN_ATTRIBUTE);

            string joinedAttributes = string.Join(Constants.ATTRIBUTE_DIVIDER, AllowedValues.Select(v => Tag.EscapeRegularExpressionCharacters(v)));
            regExp.Append(joinedAttributes);

            if (!string.IsNullOrEmpty(joinedAttributes) && AllowedRegExp.Any())
            {
                regExp.Append(Constants.ATTRIBUTE_DIVIDER); //
            }

            regExp.Append(string.Join(Constants.ATTRIBUTE_DIVIDER, AllowedRegExp));

            return regExp
                .Append(Constants.CLOSE_ATTRIBUTE)
                .Append($"\"{Constants.ANY_NORMAL_WHITESPACES}")
                .ToString();
        }
    }
}
