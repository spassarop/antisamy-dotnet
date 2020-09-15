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
using System.IO;
using System.Xml;
using OWASP.AntiSamy.Exceptions;
using OWASP.AntiSamy.Html.Model;
using Attribute = OWASP.AntiSamy.Html.Model.Attribute;
using Tag = OWASP.AntiSamy.Html.Model.Tag;

namespace OWASP.AntiSamy.Html
{
    /// <summary>
    /// Holds the model for our policy engine.
    /// </summary>
    public class Policy
    {
        public const int DEFAULT_MAX_INPUT_SIZE = 100000;
        
        private const string DEFAULT_POLICY_URI = "Resources/OWASP.AntiSamy.xml";
        private const string DEFAULT_ONINVALID = "removeAttribute";
        private const char REGEX_BEGIN = '^';
        private const char REGEX_END = '$';

        private readonly Dictionary<string, string> commonRegularExpressions;
        private readonly Dictionary<string, Attribute> commonAttributes;
        private readonly Dictionary<string, Tag> tagRules;
        private readonly Dictionary<string, Property> cssRules;
        private readonly Dictionary<string, string> directives;
        private readonly Dictionary<string, Attribute> globalAttributes;

        private List<string> tagNames;

        /// <summary> Load the policy from an XML file.</summary>
        /// <param name="file">Load a policy from the File object.</param>
        /// <exception cref="PolicyException"></exception>
        private Policy(FileInfo file)
            : this(file.FullName)
        {
        }

        /// <summary> Load the policy from an XML file.</summary>
        /// <param name="filename">Load a policy from the filename specified.</param>
        /// <exception cref="PolicyException"></exception>
        private Policy(string filename)
        {
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(filename);

                XmlNode commonRegularExpressionListNode = doc.GetElementsByTagName("common-regexps")[0];
                commonRegularExpressions = ParseCommonRegExps(commonRegularExpressionListNode);

                XmlNode directiveListNode = doc.GetElementsByTagName("directives")[0];
                directives = ParseDirectives(directiveListNode);

                XmlNode commonAttributeListNode = doc.GetElementsByTagName("common-attributes")[0];
                commonAttributes = ParseCommonAttributes(commonAttributeListNode);

                XmlNode globalAttributesListNode = doc.GetElementsByTagName("global-tag-attributes")[0];
                globalAttributes = ParseGlobalAttributes(globalAttributesListNode);

                XmlNode tagListNode = doc.GetElementsByTagName("tag-rules")[0];
                tagRules = ParseTagRules(tagListNode);

                XmlNode cssListNode = doc.GetElementsByTagName("css-rules")[0];
                cssRules = ParseCSSRules(cssListNode);
            }
            catch (PolicyException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new PolicyException($"Problem parsing policy file: {ex.Message}");
            }
        }

        /// <summary> This retrieves a Policy based on a default location ("Resources/antisamy.xml")</summary>
        /// <returns> A populated Policy object based on the XML policy file located in the default location.</returns>
        /// <exception cref="PolicyException"></exception>
        public static Policy GetInstance() => new Policy(DEFAULT_POLICY_URI);

        /// <summary> This retrieves a Policy based on the file name passed in</summary>
        /// <param name="filename">The path to the XML policy file.</param>
        /// <returns> A populated Policy object based on the XML policy file located in the location passed in.</returns>
        /// <exception cref="PolicyException"></exception>
        public static Policy GetInstance(string filename) => new Policy(filename);

        /// <summary> This retrieves a Policy based on the File object passed in</summary>
        /// <param name="file">A File object which contains the XML policy information.</param>
        /// <returns> A populated Policy object based on the XML policy file pointed to by the File parameter.</returns>
        /// <exception cref="PolicyException"></exception>
        public static Policy GetInstance(FileInfo file) => new Policy(new FileInfo(file.FullName));

        /*/// <summary> A simple method for returning on of the <common-regexp> entries by
        /// name.
        /// 
        /// </summary>
        /// <param name="name">The name of the common regexp we want to look up.
        /// </param>
        /// <returns> An AntiSamyPattern associated with the lookup name specified.
        /// </returns>
        public virtual AntiSamyPattern getRegularExpression(string name)
        {
            return (AntiSamyPattern)commonRegularExpressions[name];
        }
        */

        public string GetRegularExpression(string name) => name == null ? null : commonRegularExpressions.GetValueOrDefault(name);

        /// <summary> A simple method for returning on of the <global-attribute> entries by name.</summary>
        /// <param name="name">The name of the global-attribute we want to look up.</param>
        /// <returns> An Attribute associated with the global-attribute lookup name specified.</returns>
        public Attribute GetGlobalAttributeByName(string name) => globalAttributes.GetValueOrDefault(name);

        /// <summary> Return a directive value based on a lookup name.</summary>
        /// <returns> A string object containing the directive associated with the lookup name, or null if none is found.</returns>
        public string GetDirective(string name) => directives.GetValueOrDefault(name);

        /// <summary> Retrieves a Tag from the Policy.</summary>
        /// <param name="tagName">The name of the Tag to look up.</param>
        /// <returns> The Tag associated with the name specified, or null if none is found.</returns>
        public Tag GetTagByName(string tagName) => tagRules.GetValueOrDefault(tagName);

        /// <summary> Retrieves a CSS Property from the Policy.</summary>
        /// <param name="propertyName">The name of the CSS Property to look up.</param>
        /// <returns> The CSS Property associated with the name specified, or null if none is found.</returns>
        public Property GetPropertyByName(string propertyName) => cssRules.GetValueOrDefault(propertyName);

        /// <summary> A simple method for returning on of the <common-attribute> entries by name.</summary>
        /// <param name="name">The name of the common-attribute we want to look up.</param>
        /// <returns> An Attribute associated with the common-attribute lookup name specified.</returns>
        private Attribute GetCommonAttributeByName(string attributeName) => commonAttributes.GetValueOrDefault(attributeName);

        /// <summary> Go through <directives> section of the policy file.</summary>
        /// <param name="directiveListNode">Top level of <directives></param>
        /// <returns> A Dictionary of directives for validation behavior.</returns>
        private Dictionary<string, string> ParseDirectives(XmlNode directiveListNode)
        {
            XmlNodeList directiveNodes = directiveListNode.SelectNodes("directive");
            var directives = new Dictionary<string, string>();

            foreach (XmlNode node in directiveNodes)
            {
                if (node.NodeType == XmlNodeType.Element)
                {
                    string name = node.Attributes[0].Value;
                    if (!directives.ContainsKey(name))
                    {
                        string value = node.Attributes[1].Value;
                        directives.Add(name, value);
                    }
                }
            }

            return directives;
        }

        /// <summary> Go through <global-tag-attributes> section of the policy file.</summary>
        /// <param name="globalAttributeListNode">Top level of <global-tag-attributes></param>
        /// <returns> A Dictionary of global Attributes that need validation for every tag.</returns>
        private Dictionary<string, Attribute> ParseGlobalAttributes(XmlNode globalAttributeListNode)
        {
            XmlNodeList globalAttributeNodes = globalAttributeListNode.SelectNodes("attribute");
            var globalAttributes = new Dictionary<string, Attribute>();

            foreach (XmlNode node in globalAttributeNodes)
            {
                if (node.NodeType == XmlNodeType.Element)
                {
                    string name = node.Attributes[0].Value;
                    Attribute toAdd = GetCommonAttributeByName(name);
                    if (toAdd != null)
                    {
                        globalAttributes.Add(name, toAdd);
                    }
                    else
                    {
                        throw new PolicyException($"Global attribute '{name}' was not defined in <common-attributes>");
                    }
                }
            }

            return globalAttributes;
        }

        /// <summary> Go through the <common-regexps> section of the policy file.</summary>
        /// <param name="root">Top level of <common-regexps></param>
        /// <returns> A List of AntiSamyPattern objects.</returns>
        private Dictionary<string, string> ParseCommonRegExps(XmlNode commonRegularExpressionListNode)
        {
            XmlNodeList list = commonRegularExpressionListNode.SelectNodes("regexp");
            var commonRegularExpressions = new Dictionary<string, string>();

            foreach (XmlNode node in list)
            {
                if (node.NodeType == XmlNodeType.Element)
                {
                    string name = node.Attributes[0].Value;
                    if (!commonRegularExpressions.ContainsKey(name))
                    {
                        string value = node.Attributes[1].Value;
                        commonRegularExpressions.Add(name, value);
                    }
                }
            }

            return commonRegularExpressions;
        }

        /// <summary> Go through the <common-attributes> section of the policy file.</summary>
        /// <param name="root">Top level of <common-attributes></param>
        /// <returns> A List of Attribute objects.</returns>
        private Dictionary<string, Attribute> ParseCommonAttributes(XmlNode commonAttributeListNode)
        {
            XmlNodeList commonAttributeNodes = commonAttributeListNode.SelectNodes("attribute");
            var commonAttributes = new Dictionary<string, Attribute>();

            foreach (XmlNode node in commonAttributeNodes)
            {
                if (node.NodeType == XmlNodeType.Element)
                {
                    /*DEFAULT_ONINVALID seems to have been removed from common attributes.  Do we need this code?*/
                    string onInvalid = node.Attributes["onInvalid"]?.Value;
                    string name = node.Attributes["name"]?.Value;
                    var attribute = new Attribute(name)
                    {
                        Description = node.Attributes["description"]?.Value,
                        OnInvalid = string.IsNullOrEmpty(onInvalid) ? DEFAULT_ONINVALID : onInvalid
                    };

                    XmlNodeList regExListNode = node.SelectNodes("regexp-list");
                    if (regExListNode != null && regExListNode.Count > 0)
                    {
                        XmlNodeList regExList = regExListNode[0].SelectNodes("regexp");
                        foreach (XmlNode regExNode in regExList)
                        {
                            string regExName = regExNode.Attributes["name"]?.Value;
                            string value = regExNode.Attributes["value"]?.Value;
                            //TODO: java version uses "Pattern" class to hold regular expressions.  I'm storing them as strings below
                            //find out if I need an equiv to pattern 
                            string allowedRegEx = string.IsNullOrEmpty(regExName) ? $"{REGEX_BEGIN}{value}{REGEX_END}" : GetRegularExpression(regExName).ToString();
                        }
                    }

                    XmlNode literalListNode = node.SelectNodes("literal-list")[0];
                    if (literalListNode != null)
                    {
                        XmlNodeList literalNodes = literalListNode.SelectNodes("literal");
                        foreach (XmlNode literalNode in literalNodes)
                        {
                            string value = literalNode.Attributes["value"]?.Value;

                            if (!string.IsNullOrEmpty(value))
                            {
                                attribute.AddAllowedValue(value);
                            }
                            else if (literalNode.Value != null)
                            {
                                attribute.AddAllowedValue(literalNode.Value);
                            }
                        }
                    }

                    commonAttributes.Add(name, attribute);
                }
            }

            return commonAttributes;
        }

        /// <summary> Private method for parsing the <tag-rules> from the XML file.</summary>
        /// <param name="root">The root element for <tag-rules></param>
        /// <returns> A Dictionary<string, Tag> containing the rules.</returns>
        /// <exception cref="PolicyException"></exception>
        private Dictionary<string, Tag> ParseTagRules(XmlNode tagAttributeListNode)
        {
            var tags = new Dictionary<string, Tag>();
            XmlNodeList tagList = tagAttributeListNode.SelectNodes("tag");
            foreach (XmlNode tagNode in tagList)
            {
                if (tagNode.NodeType == XmlNodeType.Element)
                {
                    string name = tagNode.Attributes["name"]?.Value;
                    string action = tagNode.Attributes["action"]?.Value;

                    var tag = new Tag(name) { 
                        Action = action 
                    };

                    if (tagNames == null)
                    {
                        tagNames = new List<string>();
                    }

                    tagNames.Add(name);

                    XmlNodeList attributeList = tagNode.SelectNodes("attribute");
                    foreach (XmlNode attributeNode in attributeList)
                    {
                        if (!attributeNode.HasChildNodes)
                        {
                            Attribute attribute = GetCommonAttributeByName(attributeNode.Attributes["name"].Value);

                            if (attribute != null)
                            {
                                string onInvalid = attributeNode.Attributes["onInvalid"]?.Value;
                                string description = attributeNode.Attributes["description"]?.Value;

                                if (!string.IsNullOrEmpty(onInvalid))
                                {
                                    attribute.OnInvalid = onInvalid;
                                }
                                if (!string.IsNullOrEmpty(description))
                                {
                                    attribute.Description = description;
                                }

                                tag.AddAttribute((Attribute)attribute.Clone());
                            }
                            else
                            {
                                //TODO: make this work with .NET
                                //throw new PolicyException("Attribute '"+XMLUtil.getAttributeValue(attributeNode,"name")+"' was referenced as a common attribute in definition of '"+tag.getName()+"', but does not exist in <common-attributes>");
                            }
                        }
                        else
                        {
                            /* Custom attribute for this tag */
                            var attribute = new Attribute(attributeNode.Attributes["name"].Value)
                            {
                                Description = attributeNode.Attributes["description"]?.Value,
                                OnInvalid = attributeNode.Attributes["onInvalid"]?.Value
                            };

                            XmlNode regExListNode = attributeNode.SelectNodes("regexp-list")[0];
                            if (regExListNode != null)
                            {
                                XmlNodeList regExList = regExListNode.SelectNodes("regexp");
                                foreach (XmlNode regExNode in regExList)
                                {
                                    string regExName = regExNode.Attributes["name"]?.Value;
                                    string value = regExNode.Attributes["value"]?.Value;
                                    if (!string.IsNullOrEmpty(regExName))
                                    {
                                        string pattern = GetRegularExpression(regExName);
                                        if (pattern != null)
                                        {
                                            attribute.AddAllowedRegExp(pattern);
                                        }
                                        else
                                        {
                                            throw new PolicyException($"Regular expression '{regExName}' was referenced as a common regexp in definition of '{tag.Name}', but does not exist in <common-regexp>");
                                        }
                                    }
                                    else if (!string.IsNullOrEmpty(value))
                                    {
                                        //TODO: see if I need to reimplement pattern.compile
                                        attribute.AddAllowedRegExp($"{REGEX_BEGIN}{value}{REGEX_END}");
                                    }
                                }
                            }

                            XmlNode literalListNode = attributeNode.SelectNodes("literal-list")[0];
                            if (literalListNode != null)
                            {
                                XmlNodeList literalNodes = literalListNode.SelectNodes("literal");
                                foreach (XmlNode literalNode in literalNodes)
                                {
                                    string value = literalNode.Attributes["value"]?.Value;
                                    if (!string.IsNullOrEmpty(value))
                                    {
                                        attribute.AddAllowedValue(value);
                                    }
                                    else if (literalNode.Value != null)
                                    {
                                        attribute.AddAllowedValue(literalNode.Value);
                                    }
                                }
                            }
                            tag.AddAttribute(attribute);
                        }
                    }
                    tags.Add(name, tag);
                }
            }

            return tags;
        }

        /// <summary> Go through the <css-rules> section of the policy file.</summary>
        /// <param name="cssNodeList">Top level of <css-rules></param>
        /// <returns> An List of Property objects.</returns>
        /// <exception cref="PolicyException"></exception>
        private Dictionary<string, Property> ParseCSSRules(XmlNode cssNodeList)
        {
            var properties = new Dictionary<string, Property>();
            XmlNodeList propertyNodes = cssNodeList.SelectNodes("property");

            /*
		    * Loop through the list of attributes and add them to the collection.
		    */
            foreach (XmlNode propertyNode in propertyNodes)
            {
                string name = propertyNode.Attributes["name"]?.Value;
                string description = propertyNode.Attributes["description"]?.Value;
                string onInvalid = propertyNode.Attributes["onInvalid"]?.Value;

                var property = new Property(name)
                {
                    Description = description,
                    OnInvalid = string.IsNullOrEmpty(onInvalid) ? DEFAULT_ONINVALID : onInvalid
                };

                XmlNode regExListNode = propertyNode.SelectNodes("regexp-list")[0];
                if (regExListNode != null)
                {
                    /*
    				 * First go through the allowed regular expressions.
	    			 */
                    XmlNodeList regExList = regExListNode.SelectNodes("regexp");
                    foreach (XmlNode regExNode in regExList)
                    {
                        string regExName = regExNode.Attributes["name"]?.Value;
                        string value = regExNode.Attributes["value"]?.Value;
                        string pattern = GetRegularExpression(regExName);
                        if (pattern != null)
                        {
                            property.AddAllowedRegExp(pattern);
                        }
                        else if (value != null)
                        {
                            property.AddAllowedRegExp($"{REGEX_BEGIN}{value}{REGEX_END}");
                        }
                        else
                        {
                            throw new PolicyException($"Regular expression '{regExName}' was referenced as a common regexp in definition of '{property.Name}', but does not exist in <common-regexp>");
                        }
                    }
                }
                
                /*
                 * Then go through the allowed constants.
                 */
                XmlNode literalListNode = propertyNode.SelectNodes("literal-list")[0];
                if (literalListNode != null)
                {
                    XmlNodeList literalList = literalListNode.SelectNodes("literal");
                    foreach (XmlNode literalNode in literalList)
                    {
                        property.AddAllowedValue(literalNode.Attributes["value"].Value);
                    }
                }

                XmlNode shorthandListNode = propertyNode.SelectNodes("shorthand-list")[0];
                if (shorthandListNode != null)
                {
                    XmlNodeList shorthandList = shorthandListNode.SelectNodes("shorthand");
                    foreach (XmlNode shorthandNode in shorthandList)
                    {
                        property.AddShorthandRef(shorthandNode.Attributes["name"].Value);
                    }
                }

                properties.Add(name, property);
            }

            return properties;
        }
    }
}