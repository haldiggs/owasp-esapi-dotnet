<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="EncoderPage.aspx.cs" Inherits="Owasp.Esapi.Swingset.Users.Examples.EncoderPage" MasterPageFile="~/Esapi.Master" ValidateRequest="false" %>
<%@ Import Namespace="Owasp.Esapi" %>
<%-- ValidateRequest is off, but usually should rarely be --%>
<asp:Content ID="EncoderContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server">
Text to encode:
<div>
<asp:TextBox ID="txtToEncode" runat="server"></asp:TextBox>
<asp:Button ID="btnEncode" runat="server" Text="Encode" onclick="btnEncode_Click" />
</div>

HTML:
<div>
    <asp:TextBox ID="txtHtml" runat="server"></asp:TextBox>
</div>
HTML Attribute:
<div>
    <asp:TextBox ID="txtHtmlAttribute" runat="server"></asp:TextBox>
</div>
JavaScript:
<div>
    <asp:TextBox ID="txtJavascript" runat="server"></asp:TextBox>
</div>
VB Script:
<div>
    <asp:TextBox ID="txtVbScript" runat="server"></asp:TextBox>
</div>
XML:
<div>
    <asp:TextBox ID="txtXml" runat="server"></asp:TextBox>
</div>
XML Attribute:
<div>
    <asp:TextBox ID="txtXmlAttribute" runat="server"></asp:TextBox>
</div>
</asp:Content>