/*
* Copyright (c) 2009-2020, Jerry Hoff
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

        // Will hold the results of the scan
        public CleanResults Results { get; set; }
        // Policy holds the parsed attributes from the XML config file
        private readonly Policy policy;
        // All error messages live in here
        private readonly List<string> errorMessages = new List<string>();
        // Needed to parse input
        private readonly XmlDocument document = new XmlDocument();
        // Needed to represent the parsed version of the input
        private XmlDocumentFragment dom;

        public AntiSamyDomScanner(Policy policy)
        {
            InitBlock();
            this.policy = policy;
        }

        public AntiSamyDomScanner()
        {
            InitBlock();
            policy = Policy.GetInstance();
        }

        /// <summary> Main parsing engine </summary>
        /// <param name="html">A string whose contents we want to scan.</param>
        /// <returns> A <see cref="CleanResults"/> object with an <see cref="XmlDocumentFragment"/>
        ///  object and its string representation, as well as some scan statistics.</returns>
        /// <exception cref="ScanException">  ScanException </exception>
        public virtual CleanResults Scan(string html) 
        {
            if (html == null)
            {
                throw new ScanException("No input (null)");
            }

            int maxInputSize = policy.GetMaximumInputSize();

            // Ensure our input is less than the max
            if (maxInputSize < html.Length)
            {
                throw new ScanException($"File size [{html.Length}] is larger than maximum [{maxInputSize}]");
            }

            if (dom != null)
            {
                InitBlock(); // There was a scan before on the same instance
            }

            // Had problems with the &nbsp; getting double encoded, so this converts it to a literal space. This may need to be changed.
            html = html.Replace("&nbsp;", char.Parse("\u00a0").ToString());

            // We have to replace any invalid XML characters
            html = StripNonValidXmlCharacters(html);

            // Grab start time (to be put in the result set along with end time)
            var start = DateTime.Now;

            // Fixes some weirdness in HTML agility
            if (!HtmlNode.ElementsFlags.ContainsKey("iframe"))
            {
                HtmlNode.ElementsFlags.Add("iframe", HtmlElementFlag.Empty);
            }
            HtmlNode.ElementsFlags.Remove("form");

            // Let's parse the incoming HTML
            var htmlDocument = new HtmlDocument();
            htmlDocument.LoadHtml(html);

            // Add closing tags
            htmlDocument.OptionAutoCloseOnEnd = true;

            // Enforces XML rules, encodes big 5
            htmlDocument.OptionOutputAsXml = true;

            // Loop through every node now, and enforce the rules held in the policy object
            var currentChildIndex = 0;
            while (currentChildIndex < htmlDocument.DocumentNode.ChildNodes.Count)
            {
                // Grab current node
                HtmlNode tmp = htmlDocument.DocumentNode.ChildNodes[currentChildIndex];

                // This node can hold other nodes, so recursively validate
                RecursiveValidateTag(tmp);

                if (tmp.ParentNode != null)
                {
                    currentChildIndex++;
                }
            }

            // All the cleaned HTML
            string finalCleanHTML = htmlDocument.DocumentNode.InnerHtml;

            // Grab end time (to be put in the result set along with start time)
            var end = DateTime.Now;
            Results = new CleanResults(start, end, finalCleanHTML, dom, errorMessages);
            return Results;
        }

        private void InitBlock()
        {
            dom = document.CreateDocumentFragment();
            errorMessages.Clear();
        }

        /// <summary>The workhorse of the scanner. Recursively scans document elements according to the policy.
        /// This should be called implicitly through the <c>AntiSamy.Scan()</c> method.</summary>
        /// <param name="node">The node to validate.</param>
        private void RecursiveValidateTag(HtmlNode node)
        {
            HtmlNode parentNode = node.ParentNode;
            string tagName = node.Name;

            // TODO: Check this out, might not be robust enough. Check if this is needed: || tagName.ToLowerInvariant().Equals("#comment"))
            if (tagName.ToLowerInvariant() == "#text")
            {
                return;
            }

            Tag tag = policy.GetTagByName(tagName.ToLowerInvariant());
            HtmlNode tmp = null;
            
            if (tag == null || tag.Action == Policy.ACTION_FILTER)
            {
                FilterTag(node, tagName, tmp);
            }
            else if (tag.Action == Policy.ACTION_VALIDATE)
            {
                ValidateTag(node, parentNode, tagName, tag, tmp);
            }
            else if (tag.Action == Policy.ACTION_TRUNCATE)
            {
                TruncateTag(node, tagName);
            }
            else
            {
                parentNode.RemoveChild(node);
                errorMessages.Add($"The <b>{HtmlEntityEncoder.HtmlEntityEncode(tagName)}</b> tag has been removed for security reasons.");
            }
        }

        private void FilterTag(HtmlNode node, string tagName, HtmlNode tmp)
        {
            var errBuff = new StringBuilder();
            errBuff.Append(string.IsNullOrEmpty(tagName) ?
                "An unprocessable " : $"The <b>{HtmlEntityEncoder.HtmlEntityEncode(tagName.ToLowerInvariant())}</b> ");
            errBuff.Append("tag has been filtered for security reasons. The contents of the tag will remain in place.");
            errorMessages.Add(errBuff.ToString());

            ProcessChildren(node, tmp);
            PromoteChildren(node);
        }

        private void ValidateTag(HtmlNode node, HtmlNode parentNode, string tagName, Tag tag, HtmlNode tmp)
        {
            /*
            * Check to see if it's a <style> tag. We have to special case this
            * tag so we can hand it off to the custom style sheet validating parser.
            */
            if (tagName.ToLowerInvariant() == "style" && policy.GetTagByName("style") != null && !ProcessStyleTag(node, parentNode))
            {
                return;
            }

            /*
            * Go through the attributes in the tainted tag and validate them against the values we have for them.
            * If we don't have a rule for the attribute we remove the attribute.
            */
            if (!ProcessAttributes(node, parentNode, tmp, tag))
            {
                return;
            }

            ProcessChildren(node, tmp);
        }

        private void TruncateTag(HtmlNode node, string tagName)
        {
            HtmlAttributeCollection attributes = node.Attributes;

            while (attributes.Count > 0)
            {
                var errBuff = new StringBuilder()
                    .Append($"The <b>{HtmlEntityEncoder.HtmlEntityEncode(attributes[0].Name)}")
                    .Append($"</b> attribute of the <b>{HtmlEntityEncoder.HtmlEntityEncode(tagName)}</b> tag has been removed for security reasons. ")
                    .Append("This removal should not affect the display of the HTML submitted.");

                node.Attributes.Remove(attributes[0].Name);
                errorMessages.Add(errBuff.ToString());
            }

            HtmlNodeCollection childNodes = node.ChildNodes;
            int j = 0;
            int length = childNodes.Count;

            for (int i = 0; i < length; i++)
            {
                HtmlNode nodeToRemove = childNodes[j];
                if (nodeToRemove.NodeType != HtmlNodeType.Text && nodeToRemove.NodeType != HtmlNodeType.Comment)
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
            var styleScanner = new CssScanner(policy);
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
            /* TODO: If encapsulating errors, add this one if needed: ErrorMessageUtil.ERROR_CSS_TAG_MALFORMED
             *       catching with "DOMException" or equivalent.       
             */
            catch (ScanException)
            {
                // TODO: If encapsulating errors, add this one if needed: ErrorMessageUtil.ERROR_CSS_TAG_MALFORMED
                parentNode.RemoveChild(node);
                return false;
            }

            return true;
        }

        private bool ProcessAttributes(HtmlNode node, HtmlNode parentNode, HtmlNode tmp, Tag tag)
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
                    attribute = policy.GetGlobalAttributeByName(name);
                }

                bool isAttributeValid = false;

                if (name.ToLowerInvariant() == "style" && attribute != null)
                {
                    var styleScanner = new CssScanner(policy);

                    try
                    {
                        CleanResults cleanInlineStyle = styleScanner.ScanInlineStyle(value, tagName);
                        htmlAttribute.Value = cleanInlineStyle.GetCleanHtml();
                        errorMessages.AddRange(cleanInlineStyle.GetErrorMessages());
                    }
                    /* TODO: If encapsulating errors, add this one if needed: ErrorMessageUtil.ERROR_CSS_ATTRIBUTE_MALFORMED
                     *       catching with "DOMException" or equivalent, using tagName and node.getValue().       
                     */
                    catch (ScanException)
                    {
                        /* TODO: If encapsulating errors, add this one if needed: ErrorMessageUtil.ERROR_CSS_ATTRIBUTE_MALFORMED,
                         *       using tagName and node.getValue().       
                         */
                        currentAttributeIndex--;
                    }
                }
                else
                {
                    if (attribute != null)
                    {
                        // TODO: Try to find out how robust this is - do I need to do this in a loop?
                        value = HtmlEntity.DeEntitize(value);
                        string lowerCaseValue = value.ToLowerInvariant();

                        isAttributeValid = attribute.AllowedValues.Any(v => v != null && v.ToLowerInvariant() == lowerCaseValue)
                            || attribute.AllowedRegExp.Any(r => r != null && Regex.IsMatch(value, "^" + r + "$"));

                        if (!isAttributeValid)
                        {
                            var errBuff = new StringBuilder()
                                .Append($"The <b>{HtmlEntityEncoder.HtmlEntityEncode(tagName)}</b> tag contained an attribute that we couldn't process. ")
                                .Append($"The <b>{HtmlEntityEncoder.HtmlEntityEncode(name)}</b> attribute had a value of <u>{HtmlEntityEncoder.HtmlEntityEncode(value)}</u>. ")
                                .Append("This value could not be accepted for security reasons. We have chosen to ");

                            string onInvalidAction = attribute.OnInvalid;
                            if (onInvalidAction == "removeTag")
                            {
                                parentNode.RemoveChild(node);
                                errBuff.Append("remove the <b>" + HtmlEntityEncoder.HtmlEntityEncode(tagName) + "</b> tag and its contents in order to process this input. ");
                            }
                            else if (onInvalidAction == "filterTag")
                            {
                                // Remove the attribute and keep the rest of the tag.
                                ProcessChildren(node, tmp);
                                PromoteChildren(node);
                                errBuff.Append($"filter the <b>{HtmlEntityEncoder.HtmlEntityEncode(tagName)}</b> tag and leave its contents in place so that we could process this input.");
                            }
                            else
                            {
                                node.Attributes.Remove(attribute.Name);
                                currentAttributeIndex--;
                                errBuff.Append($"remove the <b>{HtmlEntityEncoder.HtmlEntityEncode(name)}</b> attribute from the tag and leave everything else in place so that we could process this input.");
                            }

                            errorMessages.Add(errBuff.ToString());

                            if (onInvalidAction == "removeTag" || onInvalidAction == "filterTag")
                            {
                                return false; // Can't process any more if we remove/filter the tag	
                            }
                        }
                    }
                    else
                    {
                        var errBuff = new StringBuilder()
                            .Append($"The <b>{HtmlEntityEncoder.HtmlEntityEncode(name)}")
                            .Append($"</b> attribute of the <b>{HtmlEntityEncoder.HtmlEntityEncode(tagName)}</b> tag has been removed for security reasons. ")
                            .Append("This removal should not affect the display of the HTML submitted.");

                        errorMessages.Add(errBuff.ToString());
                        node.Attributes.Remove(name);
                        currentAttributeIndex--;
                    } // End if attribute is or is not found in policy file
                } // End if style.equals("name") 

                currentAttributeIndex++;
            } // End while loop through attributes 

            return true;
        }

        private void ProcessChildren(HtmlNode node, HtmlNode tmp)
        {
            int childNodeIndex = 0;
            while (childNodeIndex < node.ChildNodes.Count)
            {
                tmp = node.ChildNodes[childNodeIndex];
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

            parent.RemoveChild(node);
        }
        
        private string StripNonValidXmlCharacters(string textToClean)
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

        // TODO: Use in future refactor or delete, its purpose is to build errors from constants and parameters.
        private void AddError(string errorKey, object[] objs)
        {
            errorMessages.Add(errorKey); // Here, ErrorMessageUtil would be used with errorKey and obj.
        }
    }
}
