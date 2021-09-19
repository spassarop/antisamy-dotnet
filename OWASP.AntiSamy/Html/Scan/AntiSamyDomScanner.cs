/*
 * Copyright (c) 2009-2020, Jerry Hoff, Sebastián Passaro
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
using System.Text.RegularExpressions;
using System.Xml;
using HtmlAgilityPack;
using OWASP.AntiSamy.Css;
using OWASP.AntiSamy.Exceptions;
using OWASP.AntiSamy.Html.Model;
using OWASP.AntiSamy.Html.Util;
using Attribute = OWASP.AntiSamy.Html.Model.Attribute;

namespace OWASP.AntiSamy.Html.Scan
{
    /// <summary> This is where the magic lives. All the scanning/filtration logic resides here, but it should not be called
    /// directly. All scanning should be done through a <see cref="AntiSamy"/><c>.Scan()</c> method.</summary>
    internal class AntiSamyDomScanner
    {
        private const string EMPTY_CSS_COMMENT = "/* */";
        private readonly Regex CONDITIONAL_DIRECTIVES = new Regex(@"<?!?\[\s*(?:end)?if[^]]*\]>?", RegexOptions.Compiled);
        private readonly Regex PROCESSING_INSTRUCTION_REGEX = new Regex(@"^<\?\s*.*?\s*\?>$", RegexOptions.Compiled);
        private readonly Tag BASIC_EMBED_TAG = new Tag("param", Constants.ACTION_VALIDATE, new Dictionary<string, Attribute> {
                    { "name", new Attribute("name", null, null, new List<string>{ ".*"}, new List<string>()) },
                    { "value", new Attribute("value", null, null, new List<string>{ ".*"}, new List<string>()) }
                });

        // Will hold the results of the scan
        public CleanResults Results { get; set; }
        // Policy holds the parsed attributes from the XML config file
        public Policy Policy { private get; set; }
        // All error messages live in here
        private readonly List<string> errorMessages = new List<string>();

        public AntiSamyDomScanner(Policy policy)
        {
            InitBlock();
            this.Policy = policy;
        }

        public AntiSamyDomScanner()
        {
            InitBlock();
            Policy = Policy.GetInstance();
        }

        /// <summary> Main parsing engine </summary>
        /// <param name="html">A string whose contents we want to scan.</param>
        /// <returns> A <see cref="CleanResults"/> object with an <see cref="XmlDocumentFragment"/>
        ///  object and its string representation, as well as some scan statistics.</returns>
        /// <exception cref="ScanException"/>
        public CleanResults Scan(string html) 
        {
            if (html == null)
            {
                throw new ScanException("No input (null).");
            }

            if (Results != null)
            {
                InitBlock(); // There was a scan before on the same instance
            }

            // Ensure our input is less than the max
            if (Policy.MaxInputSize < html.Length)
            {
                AddError(Constants.ERROR_SIZE_TOOLARGE, html.Length, Policy.MaxInputSize);
                throw new ScanException(errorMessages.First());
            }

            // Had problems with the &nbsp; getting double encoded, so this converts it to a literal space. This may need to be changed.
            html = html.Replace("&nbsp;", char.Parse("\u00a0").ToString());
            // We have to replace any invalid XML characters
            html = StripNonValidXmlCharacters(html);

            // Fixes some weirdness in HTML agility
            if (!HtmlNode.ElementsFlags.ContainsKey("iframe"))
            {
                HtmlNode.ElementsFlags.Add("iframe", HtmlElementFlag.Empty);
            }
            HtmlNode.ElementsFlags.Remove("form");

            var htmlDocument = new HtmlDocument
            {
                OptionAutoCloseOnEnd = true, // Add closing tags
                OptionMaxNestedChildNodes = Constants.MAX_NESTED_TAGS, // TODO: Add directive for this like in MaxInputSize?
                OptionOutputAsXml = true, // Enforces XML rules, encodes big 5
                OptionXmlForceOriginalComment = true // Fix provided by the library for weird added spaces in HTML comments
            };

            // Grab start time (to be put in the result set along with end time)
            var start = DateTime.Now;

            try
            {
                // Let's parse the incoming HTML
                htmlDocument.LoadHtml(html);
                // Loop through every node now, and enforce the rules held in the policy object
                ProcessChildren(htmlDocument.DocumentNode);
            }
            catch (Exception exc)
            {
                if (!(exc is ScanException))
                {
                    throw new ScanException("There was an error while performing the scan.", exc);
                }
                else
                {
                    throw;
                }
            }

            // All the cleaned HTML
            string finalCleanHTML = Policy.PreservesSpace ? htmlDocument.DocumentNode.InnerHtml : htmlDocument.DocumentNode.InnerHtml.Trim();

            // Encode special/international characters if stated by policy
            if (Policy.EntityEncodesInternationalCharacters)
            {
                finalCleanHTML = SpecialCharactersEncoder.Encode(finalCleanHTML);
            }

            // Grab end time (to be put in the result set along with start time)
            var end = DateTime.Now;
            Results = new CleanResults(start, end, finalCleanHTML, errorMessages);
            return Results;
        }

        private void InitBlock()
        {
            errorMessages.Clear();
        }

        /// <summary>The workhorse of the scanner. Recursively scans document elements according to the policy.
        /// This should be called implicitly through the <c>AntiSamy.Scan()</c> method.</summary>
        /// <param name="node">The node to validate.</param>
        private void RecursiveValidateTag(HtmlNode node)
        {
            HtmlNode parentNode = node.ParentNode;
            string tagName = node.Name;

            if (node is HtmlTextNode)
            {
                if (HtmlNode.IsCDataElement(node.Name))
                {
                    StripCData(node);
                }
                node.InnerHtml = System.Net.WebUtility.HtmlDecode(node.InnerHtml);
                return;
            }

            if (IsProcessingInstruction(node))
            {
                RemoveProcessingInstruction(node);
                return;
            }

            if (node is HtmlCommentNode commentNode)
            {
                ProcessCommentNode(commentNode);
                return;
            }

            if (node.NodeType == HtmlNodeType.Element && !node.ChildNodes.Any() && RemoveDisallowedEmpty(node)) 
            { 
                return;
            }

            Tag tag = Policy.GetTagByName(tagName.ToLowerInvariant());

            /*
             * If <param> and no policy and ValidatesParamAsEmbed and policy in place for <embed> and <embed> 
             * policy is to validate, use custom policy to get the tag through to the validator.
             */
            bool isMasqueradingParam = IsMasqueradingParam(tag, Policy.GetTagByName("embed"), tagName.ToLowerInvariant());
            if (isMasqueradingParam)
            {
                tag = BASIC_EMBED_TAG;
            }

            if (tag == null && Policy.EncodesUnknownTag || tag != null && tag.Action == Constants.ACTION_ENCODE)
            {
                EncodeTag(node, tagName);
            }
            else if (tag == null || tag.Action == Constants.ACTION_FILTER)
            {
                FilterTag(node, tag, tagName);
            }
            else if (tag.Action == Constants.ACTION_VALIDATE)
            {
                ValidateTag(node, parentNode, tagName, tag, isMasqueradingParam);
            }
            else if (tag.Action == Constants.ACTION_TRUNCATE)
            {
                TruncateTag(node, tagName);
            }
            else
            {
                // If we reached this it means the tag's action is "remove", which means to remove the tag (including its contents).
                AddError(Constants.ERROR_TAG_DISALLOWED, HtmlEntityEncoder.HtmlEntityEncode(tagName));
                RemoveNode(node);
            }
        }

        private bool IsMasqueradingParam(Tag tag, Tag embedTag, string tagName)
        {
            return tag == null && Policy.ValidatesParamAsEmbed && tagName.ToLowerInvariant() == "param"
                && embedTag != null && embedTag.Action == Constants.ACTION_VALIDATE;
        }

        private void StripCData(HtmlNode node)
        {
            AddError(Constants.ERROR_CDATA_FOUND, HtmlEntityEncoder.HtmlEntityEncode(node.InnerHtml));

            HtmlNode parent = node.ParentNode;
            HtmlTextNode textNode = parent.OwnerDocument.CreateTextNode(node.InnerText);
            parent.InsertBefore(textNode, node);
            parent.RemoveChild(node);
        }

        private void EncodeTag(HtmlNode node, string tagName)
        {
            AddError(Constants.ERROR_TAG_ENCODED, HtmlEntityEncoder.HtmlEntityEncode(tagName));

            ProcessChildren(node);
            /*
            * Transform the tag to text, HTML-encode it and promote the children. 
            * The tag will be kept in the fragment as one or two text Nodes located 
            * before and after the children; representing how the tag used to wrap them.
            */
            EncodeAndPromoteChildren(node);
        }

        private void EncodeAndPromoteChildren(HtmlNode node)
        {
            HtmlNode parent = node.ParentNode;
            HtmlTextNode openingTag = parent.OwnerDocument.CreateTextNode(NodeToString(node));
            parent.InsertBefore(openingTag, node);

            if (node.HasChildNodes)
            {
                HtmlTextNode closingTag = parent.OwnerDocument.CreateTextNode("</" + node.Name + ">");
                parent.InsertBefore(closingTag, node.NextSibling);
            }

            PromoteChildren(node);
        }

        private bool RemoveDisallowedEmpty(HtmlNode node)
        {
            if (!IsAllowedEmptyTag(node.Name))
            {
                // Wasn't in the list of allowed elements, so we'll nuke it.
                AddError(Constants.ERROR_TAG_EMPTY, HtmlEntityEncoder.HtmlEntityEncode(node.Name));
                RemoveNode(node);
                return true;
            }

            return false;
        }

        private void RemoveNode(HtmlNode node)
        {
            HtmlNode parent = node.ParentNode;
            // Remove node
            if (parent != null)
            {
                parent.RemoveChild(node);
                // If parent is empty and is not allowed to be, remove it.
                if (parent.NodeType == HtmlNodeType.Element && !parent.ChildNodes.Any() && !IsAllowedEmptyTag(parent.Name))
                {
                    RemoveNode(parent);
                }
            }
        }

        private bool IsAllowedEmptyTag(string tagName) => tagName == "head" || Policy.GetAllowedEmptyTags().Matches(tagName);
        
        private bool IsProcessingInstruction(HtmlNode node)
        {
            // HtmlAgilityPack treats processing instructions as comment nodes. 
            // Also it does not provide a way to identify the specific node type.
            return node is HtmlCommentNode commentNode && PROCESSING_INSTRUCTION_REGEX.IsMatch(commentNode.OuterHtml);
        }

        private void RemoveProcessingInstruction(HtmlNode node)
        {
            // It makes sense to print the outer, inner probably won't have any text.
            AddError(Constants.ERROR_PI_FOUND, HtmlEntityEncoder.HtmlEntityEncode(node.OuterHtml));
            RemoveNode(node);
        }

        private void ProcessCommentNode(HtmlCommentNode node)
        {
            if (!Policy.PreservesComments)
            {
                node.ParentNode.RemoveChild(node);
            }
            else
            {
                string value = node.Comment;
                // Strip conditional directives regardless of the PRESERVE_COMMENTS setting.
                if (value != null)
                {
                    node.Comment = CONDITIONAL_DIRECTIVES.Replace(value, string.Empty);
                }
            }
        }

        private void FilterTag(HtmlNode node, Tag tag, string tagName)
        {
            AddError(tag == null ? Constants.ERROR_TAG_NOT_IN_POLICY : Constants.ERROR_TAG_FILTERED, HtmlEntityEncoder.HtmlEntityEncode(tagName));

            ProcessChildren(node);
            PromoteChildren(node);
        }

        private void ValidateTag(HtmlNode node, HtmlNode parentNode, string tagName, Tag tag, bool isMasqueradingParam)
        {
            // If doing <param> as <embed>, now is the time to convert it.
            string nameAttributeValue = null;
            if (isMasqueradingParam)
            {
                nameAttributeValue = node.Attributes["name"]?.Value;
                if (!string.IsNullOrEmpty(nameAttributeValue))
                {
                    string valueAttributeValue = node.Attributes["value"]?.Value;
                    node.SetAttributeValue(nameAttributeValue, valueAttributeValue);
                    node.SetAttributeValue("name", null);
                    node.SetAttributeValue("value", null);
                    tag = Policy.GetTagByName("embed");
                }
            }

            /*
            * Check to see if it's a <style> tag. We have to special case this
            * tag so we can hand it off to the custom style sheet validating parser.
            */
            if (tagName.ToLowerInvariant() == "style" && Policy.GetTagByName("style") != null && !ProcessStyleTag(node, parentNode))
            {
                return;
            }

            /*
            * Go through the attributes in the tainted tag and validate them against the values we have for them.
            * If we don't have a rule for the attribute we remove the attribute.
            */
            if (!ProcessAttributes(node, tag))
            {
                return;
            }

            if (Policy.DoesNotFollowAnchors && tagName.ToLowerInvariant() == "a")
            {
                node.SetAttributeValue("rel", "nofollow");
            }

            ProcessChildren(node);

            // If we have been dealing with a <param> that has been converted to an <embed>, convert it back.
            if (isMasqueradingParam && !string.IsNullOrEmpty(nameAttributeValue))
            {
                string valueAttributeValue = node.Attributes[nameAttributeValue]?.Value;
                node.SetAttributeValue("name", nameAttributeValue);
                node.SetAttributeValue("value", string.IsNullOrEmpty(valueAttributeValue) ? string.Empty : valueAttributeValue);
                
                // Original attribute may have been removed already by the validation
                if (node.Attributes[nameAttributeValue] != null)
                {
                    node.Attributes.Remove(node.Attributes[nameAttributeValue]);
                }
            }
        }

        private void TruncateTag(HtmlNode node, string tagName)
        {
            HtmlAttributeCollection attributes = node.Attributes;

            while (attributes.Count > 0)
            {
                AddError(Constants.ERROR_ATTRIBUTE_NOT_IN_POLICY,
                    HtmlEntityEncoder.HtmlEntityEncode(tagName), 
                    HtmlEntityEncoder.HtmlEntityEncode(attributes[0].Name),
                    HtmlEntityEncoder.HtmlEntityEncode(attributes[0].Value));

                node.Attributes.Remove(attributes[0].Name);
            }

            HtmlNodeCollection childNodes = node.ChildNodes;
            int j = 0;
            int length = childNodes.Count;

            for (int i = 0; i < length; i++)
            {
                HtmlNode nodeToRemove = childNodes[j];
                if (nodeToRemove.NodeType != HtmlNodeType.Text)
                {
                    node.RemoveChild(nodeToRemove);
                }
                else
                {
                    j++;
                }
            }
        }

        /// <summary>Invokes the CSS parser on the element.</summary>
        /// <param name="node">The <see cref="HtmlNode"/> to scan.</param>
        /// <param name="parentNode">The parent of the node.</param>
        /// <returns><see langword="true"/> if processing ended with no exceptions.</returns>
        private bool ProcessStyleTag(HtmlNode node, HtmlNode parentNode)
        {
            var styleScanner = new CssScanner(Policy);
            try
            {
                CleanResults cleanStyleSheet = styleScanner.ScanStyleSheet(node.FirstChild.InnerHtml);
                errorMessages.AddRange(cleanStyleSheet.GetErrorMessages());

                /*
                 * If IE gets an empty style tag, i.e. <style/> it will break all CSS on the page. I wish I
                 * was kidding. So, if after validation no CSS properties are left, we would normally be left
                 * with an empty style tag and break all CSS. To prevent that, we have this check.
                 */
                string cleanHtml = cleanStyleSheet.GetCleanHtml();
                node.FirstChild.InnerHtml = string.IsNullOrEmpty(cleanHtml) ? EMPTY_CSS_COMMENT : cleanHtml;
            }
            catch (Exception exc)
            {
                if (exc is ScanException || exc is ParseException)
                {
                    AddError(Constants.ERROR_CSS_TAG_MALFORMED, HtmlEntityEncoder.HtmlEntityEncode(node.FirstChild.InnerHtml));

                    parentNode.RemoveChild(node);
                    return false;
                }
                else
                {
                    throw;
                }
            }

            return true;
        }

        private bool ProcessAttributes(HtmlNode node, Tag tag)
        {
            string tagName = tag.Name;
            int currentAttributeIndex = 0;
            while (currentAttributeIndex < node.Attributes.Count)
            {
                HtmlAttribute htmlAttribute = node.Attributes[currentAttributeIndex];
                string name = htmlAttribute.Name;
                string value = htmlAttribute.Value;
                Attribute attribute = tag.GetAttributeByName(name);

                if (attribute == null)
                {
                    attribute = Policy.GetGlobalAttributeByName(name);
                    
                    // Not a global attribute, perhaps it is a dynamic attribute, if allowed.
                    if (attribute == null && Policy.AllowsDynamicAttributes)
                    {
                        attribute = Policy.GetDynamicAttributeByName(name);
                    }
                }

                if (name.ToLowerInvariant() == "style" && attribute != null)
                {
                    var styleScanner = new CssScanner(Policy);

                    try
                    {
                        CleanResults cleanInlineStyle = styleScanner.ScanInlineStyle(value, tagName);
                        htmlAttribute.Value = cleanInlineStyle.GetCleanHtml();
                        errorMessages.AddRange(cleanInlineStyle.GetErrorMessages());
                    }
                    catch (Exception exc)
                    {
                        if (exc is ScanException || exc is ParseException)
                        {
                            AddError(Constants.ERROR_CSS_ATTRIBUTE_MALFORMED,
                                HtmlEntityEncoder.HtmlEntityEncode(value), HtmlEntityEncoder.HtmlEntityEncode(tagName));

                            node.Attributes.Remove(name);
                            currentAttributeIndex--;
                        }
                        else
                        {
                            throw;
                        }
                    }
                }
                else
                {
                    if (attribute != null)
                    {
                        value = HtmlEntity.DeEntitize(value);
                        string lowerCaseValue = value.ToLowerInvariant();

                        bool isAttributeValid = attribute.AllowedValues.Any(v => v != null && v.ToLowerInvariant() == lowerCaseValue)
                            || attribute.AllowedRegExp.Any(r => r != null && Regex.IsMatch(value, "^" + r + "$"));

                        if (!isAttributeValid)
                        {
                            string onInvalidAction = attribute.OnInvalid;
                            if (onInvalidAction == "removeTag")
                            {
                                RemoveNode(node);
                                AddError(Constants.ERROR_ATTRIBUTE_INVALID_REMOVED, 
                                    HtmlEntityEncoder.HtmlEntityEncode(tagName), 
                                    HtmlEntityEncoder.HtmlEntityEncode(name), 
                                    HtmlEntityEncoder.HtmlEntityEncode(value));
                            }
                            else if (onInvalidAction == "filterTag")
                            {
                                // Remove the node and move up the rest that was inside the tag after processing
                                ProcessChildren(node);
                                PromoteChildren(node);
                                AddError(Constants.ERROR_ATTRIBUTE_CAUSE_FILTER,
                                    HtmlEntityEncoder.HtmlEntityEncode(tagName), 
                                    HtmlEntityEncoder.HtmlEntityEncode(name), 
                                    HtmlEntityEncoder.HtmlEntityEncode(value));
                            }
                            else if (onInvalidAction == "encodeTag")
                            {
                                // Encode the node and move up the rest that was inside the tag after processing
                                ProcessChildren(node);
                                EncodeAndPromoteChildren(node); 
                                AddError(Constants.ERROR_ATTRIBUTE_CAUSE_ENCODE,
                                    HtmlEntityEncoder.HtmlEntityEncode(tagName), 
                                    HtmlEntityEncoder.HtmlEntityEncode(name), 
                                    HtmlEntityEncoder.HtmlEntityEncode(value));
                            }
                            else
                            {
                                // Just remove the attribute
                                node.Attributes.Remove(attribute.Name);
                                currentAttributeIndex--;
                                AddError(Constants.ERROR_ATTRIBUTE_INVALID, 
                                    HtmlEntityEncoder.HtmlEntityEncode(tagName), 
                                    HtmlEntityEncoder.HtmlEntityEncode(name), 
                                    HtmlEntityEncoder.HtmlEntityEncode(value));
                            }

                            if (new string[] { "removeTag", "filterTag", "encodeTag" }.Contains(onInvalidAction))
                            {
                                return false; // Can't process any more if we remove/filter/encode the tag	
                            }
                        }
                    }
                    else
                    {
                        AddError(Constants.ERROR_ATTRIBUTE_NOT_IN_POLICY,
                            HtmlEntityEncoder.HtmlEntityEncode(tagName), 
                            HtmlEntityEncoder.HtmlEntityEncode(name), 
                            HtmlEntityEncoder.HtmlEntityEncode(value));
                        node.Attributes.Remove(name);
                        currentAttributeIndex--;
                    }
                }

                currentAttributeIndex++;
            }

            return true;
        }

        private void ProcessChildren(HtmlNode node)
        {
            int childNodeIndex = 0;
            while (childNodeIndex < node.ChildNodes.Count)
            {
                HtmlNode tmp = node.ChildNodes[childNodeIndex];
                // This node can hold other nodes, so recursively validate
                RecursiveValidateTag(tmp);
                if (tmp.ParentNode != null)
                {
                    childNodeIndex++;
                }
            }
        }

        private void PromoteChildren(HtmlNode node)
        {
            HtmlNodeCollection nodeList = node.ChildNodes;
            HtmlNode parent = node.ParentNode;

            while (nodeList.Count > 0)
            {
                HtmlNode removeNode = node.RemoveChild(nodeList[0]);
                parent.InsertBefore(removeNode, node);
            }

            RemoveNode(node);
        }
        
        private static string StripNonValidXmlCharacters(string textToClean)
        {
            if (string.IsNullOrEmpty(textToClean))
            {
                return string.Empty; // Vacancy test.
            }

            var cleanText = new StringBuilder(); // Used to hold the output.
            char current; // Used to reference the current character.

            for (int i = 0; i < textToClean.Length; i++)
            {
                current = textToClean[i]; // NOTE: No IndexOutOfBoundsException caught here; it should not happen.
                if ((current == 0x9) 
                    || (current == 0xA) 
                    || (current == 0xD) 
                    || ((current >= 0x20) && (current <= 0xD7FF)) 
                    || ((current >= 0xE000) && (current <= 0xFFFD)) 
                    || ((current >= 0x10000) && (current <= 0x10FFFF)))
                {
                    cleanText.Append(current);
                }
            }

            return cleanText.ToString();
        }

        private static string NodeToString(HtmlNode node)
        {
            var nodeToString = new StringBuilder("<" + node.Name);

            foreach (HtmlAttribute attribute in node.GetAttributes())
            {
                nodeToString
                    .Append(' ')
                    .Append(HtmlEntityEncoder.HtmlEntityEncode(attribute.Name))
                    .Append("=\"")
                    .Append(HtmlEntityEncoder.HtmlEntityEncode(attribute.Value))
                    .Append('"');
            }
            if (node.HasChildNodes)
            {
                nodeToString.Append('>');
            }
            else
            {
                nodeToString.Append("/>");
            }
            return nodeToString.ToString();
        }

        private void AddError(string errorKey, params object[] arguments)
        {
            errorMessages.Add(ErrorMessageUtil.GetMessage(errorKey, arguments));
        }
    }
}
