/*
* Copyright (c) 2008-2020, Arshan Dabirsiaghi, Jason Li, Kristian Rosenvold, Sebastián Passaro
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
using System.Xml;

namespace OWASP.AntiSamy.Html.Util
{
    /// <summary>
    /// Holds the model for our policy engine.
    /// </summary>
    internal static class PolicyParserUtil
    {
        /// <summary>Get the list of nodes descending two levels, based on the tag names provided.</summary>
        /// <param name="parent">The parent <see cref="XmlElement"/>.</param>
        /// <param name="childrenName">Name of the first level children.</param>
        /// <param name="grandchildrenName">Name of the second level children.</param>
        /// <returns></returns>
        internal static List<XmlElement> GetGrandchildrenByTagNames(XmlElement parent, string childrenName, string grandchildrenName)
        {
            XmlNodeList childrenNodes = parent.SelectNodes(childrenName);
            if (XmlUtil.IsXmlNodeListNullOrEmpty(childrenNodes)) 
            { 
                return new List<XmlElement>(); 
            }

            XmlNode firstNode = childrenNodes.Item(0);
            return GetChildrenByTagName(firstNode, grandchildrenName);
        }

        /// <summary>Get the list of children which have the provided tag name.</summary>
        /// <param name="parent">The parent <see cref="XmlNode"/>.</param>
        /// <param name="childrenName">Name of the first level children.</param>
        /// <returns></returns>
        internal static List<XmlElement> GetChildrenByTagName(XmlNode parent, string childrenName)
        {
            XmlNodeList childrenNodes = parent.SelectNodes(childrenName);
            return XmlUtil.IsXmlNodeListNullOrEmpty(childrenNodes) ? 
                new List<XmlElement>() : new List<XmlElement>(childrenNodes.Cast<XmlElement>());
        }

        /// <summary>Get the string from XML element value or "value" attribute defined in the grandchildren of the provided <see cref="XmlElement"/>.</summary>
        /// <param name="parent">The parent <see cref="XmlElement"/>.</param>
        /// <param name="childrenName">Name of the first level children.</param>
        /// <param name="grandchildrenName">Name of the second level children.</param>
        /// <param name="attributeName">Name of the XML attribute to look for in grandchildren elements.</param>
        /// <returns>A list with the values.</returns>
        internal static List<string> GetAttributeOrValueFromGrandchildren(XmlElement parent, string childrenName, string grandchildrenName, string attributeName)
        {
            var values = new List<string>();
            foreach (XmlElement element in GetGrandchildrenByTagNames(parent, childrenName, grandchildrenName))
            {
                string value = XmlUtil.GetAttributeValue(element, attributeName);

                if (!string.IsNullOrEmpty(value))
                {
                    values.Add(value);
                }
                else if (element.Value != null)
                {
                    values.Add(element.Value);
                }
            }
            return values;
        }
    }
}
