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

using System.Text;
using System.Xml;

namespace OWASP.AntiSamy.Html.Util
{
    internal static class XmlUtil
    {
        /// <summary> Helper function for quickly retrieving an attribute from a given element.</summary>
        /// <param name="element">The document element from which to pull the attribute value.</param>
        /// <param name="attributeName">The name of the attribute.</param>
        /// <returns> The value of the attribute contained within the element.</returns>
        public static string GetAttributeValue(XmlElement element, string attributeName) => Decode(element.GetAttribute(attributeName));

        /// <summary>Helper function for quickly retrieving an integer value of a given <see cref="XmlElement"/>.</summary>
        /// <param name="element">The document element from which to pull the integer value.</param>
        /// <param name="tagName">The name of the node.</param>
        /// <param name="defaultValue">The default value of the node if it's value can't be processed.</param>
        /// <returns>The integer value of the given node in the element passed in.</returns>
        public static int GetIntValue(XmlElement element, string tagName, int defaultValue)
        {
            if (!int.TryParse(GetTextValue(element, tagName), out int intValue))
            {
                intValue = defaultValue;
            }

            return intValue;
        }

        /// <summary> Helper function for quickly retrieving a string value of a given XML element.</summary>
        /// <param name="element">The document element from which to pull the string value.</param>
        /// <param name="tagName">The name of the node.</param>
        /// <returns> The string value of the given node in the element passed in.</returns>
        public static string GetTextValue(XmlElement element, string tagName)
        {
            string textValue = null;
            XmlNodeList nodeList = element.GetElementsByTagName(tagName);
            if (nodeList != null && nodeList.Count > 0)
            {
                var xmlElement = (XmlElement)nodeList.Item(0);
                textValue = xmlElement.FirstChild != null ? xmlElement.FirstChild.Value : string.Empty;
            }

            return Decode(textValue);
        }

        /// <summary> Helper function for quickly retrieving an boolean value of a given XML element.</summary>
        /// <param name="element">The document element from which to pull the boolean value.</param>
        /// <param name="tagName">The name of the node.</param>
        /// <returns> The boolean value of the given node in the element passed in.</returns>
        public static bool GetBooleanValue(XmlElement element, string tagName)
        {
            bool boolValue = false;
            XmlNodeList nodeList = element.GetElementsByTagName(tagName);

            if (nodeList != null && nodeList.Count > 0)
            {
                var xmlElement = (XmlElement)nodeList.Item(0);
                boolValue = xmlElement.FirstChild.Value.Equals("true");
            }

            return boolValue;
        }

        /// <summary> Helper function for quickly retrieving an boolean value of a given
        /// XML element, with a default initialization value passed in a parameter.</summary>
        /// <param name="element">The document element from which to pull the boolean value.</param>
        /// <param name="tagName">The name of the node.</param>
        /// <param name="defaultValue">The default value of the node if it's value can't be processed.</param>
        /// <returns> The boolean value of the given node in the element passed in.</returns>
        public static bool GetBooleanValue(XmlElement element, string tagName, bool defaultValue)
        {
            bool boolValue = defaultValue;
            XmlNodeList nodeList = element.GetElementsByTagName(tagName);

            if (nodeList != null && nodeList.Count > 0)
            {
                var xmlElement = (XmlElement)nodeList.Item(0);
                boolValue = xmlElement.FirstChild.Value != null ? "true".Equals(xmlElement.FirstChild.Value) : defaultValue;
            }

            return boolValue;
        }

        /// <summary> Helper function for decoding XML entities.</summary>
        /// <param name="str">The XML-encoded string to decode.</param>
        /// <returns> An XML-decoded string.</returns>
        public static string Decode(string str) => str == null ?
                null : new StringBuilder(str).Replace("&gt;", ">")
                                             .Replace("&lt;", "<")
                                             .Replace("&quot;", "\"")
                                             .Replace("&amp;", "&")
                                             .ToString();

        /// <summary> Helper function for encoding XML entities.</summary>
        /// <param name="str">The XML-encoded string to encode.</param>
        /// <returns> An XML-encoded string.</returns>
        public static string Encode(string str) => str == null ?
                null : new StringBuilder(str).Replace(">", "&gt;")
                                             .Replace("<", "&lt;")
                                             .Replace("\"", "&quot;")
                                             .Replace("&", "&amp;")
                                             .ToString();

        /// <summary>Helper function to know if a <see cref="XmlNodeList"/> object is null or empty.</summary>
        /// <param name="nodeList">The node list to check.</param>
        public static bool IsXmlNodeListNullOrEmpty(XmlNodeList nodeList) => nodeList == null || nodeList.Count == 0;
    }
}
