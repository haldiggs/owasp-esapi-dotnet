<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="Owasp.Esapi.Swingset.Users.Default" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="DefaultContent" ContentPlaceHolderID="EsapiContentPlaceHolder" runat="server">
    <ul>
    <li><asp:HyperLink ID="hlAccessReferenceMap" runat="server"  NavigateUrl="~/Users/AccessReferenceMap.aspx">AccessReferenceMap</asp:HyperLink></li>
    <li><asp:HyperLink ID="hlEncoder" runat="server"  NavigateUrl="~/Users/Encoder.aspx">Encoder</asp:HyperLink></li>
    <li><asp:HyperLink ID="hlEncryptor" runat="server"  NavigateUrl="~/Users/Encryptor.aspx">Encryptor</asp:HyperLink></li>
    <li><asp:HyperLink ID="hlIntrusionDetector" runat="server"  NavigateUrl="~/Users/IntrusionDetector.aspx">Intrusion Detector</asp:HyperLink></li>
    <li><asp:HyperLink ID="hlRandomizer" runat="server"  NavigateUrl="~/Users/Randomizer.aspx">Randomizer</asp:HyperLink></li>
    </ul>
    <ul>
    <li><asp:HyperLink ID="hlChangePassword" runat="server"  NavigateUrl="~/Users/ChangePassword.aspx">Change Password</asp:HyperLink></li>
    <li><asp:LoginStatus ID="EsapiLoginStatus" runat="server"  OnLoggingOut="EsapiLoginStatus_LoggingOut" /></li>
    </ul>
</asp:Content>
